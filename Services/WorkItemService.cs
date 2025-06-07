using SecurityStats.Models;
using System.Text;

namespace SecurityStats.Services
{
    public class WorkItemService
    {
        private readonly UserService _userService;
        private readonly GitHubAppService _gitHubAppService;
        private readonly ILogger<WorkItemService> _logger;

        public WorkItemService(UserService userService, GitHubAppService gitHubAppService, ILogger<WorkItemService> logger)
        {
            _userService = userService;
            _gitHubAppService = gitHubAppService;
            _logger = logger;
        }

        public async Task<GitHubIssue?> CreateWorkItemForVulnerabilityAsync(string userId, VulnerabilityBase vulnerability, string repository)
        {
            try
            {
                // Check if work item already exists for this vulnerability
                var existingWorkItem = await _userService.GetExistingWorkItemAsync(userId, vulnerability.Id, repository, vulnerability.Type);
                if (existingWorkItem != null)
                {
                    _logger.LogDebug("Work item already exists for vulnerability {VulnId} in {Repository} (Issue #{IssueNumber})", 
                        vulnerability.Id, repository, existingWorkItem.GitHubIssueNumber);
                    return null;
                }

                var config = await _userService.GetWorkItemConfigurationAsync(userId);
                if (config == null || !config.IsEnabled)
                {
                    _logger.LogDebug("Work item creation disabled for user {UserId}", userId);
                    return null;
                }

                var applicableRule = FindApplicableRule(config, vulnerability);
                if (applicableRule == null)
                {
                    _logger.LogDebug("No applicable rule found for vulnerability {VulnId} with severity {Severity}", 
                        vulnerability.Id, vulnerability.Severity);
                    return null;
                }

                var installation = await _userService.GetActiveGitHubInstallationAsync(userId);
                if (installation == null)
                {
                    _logger.LogWarning("No active GitHub installation found for user {UserId}", userId);
                    return null;
                }

                var repoParts = repository.Split('/');
                if (repoParts.Length != 2)
                {
                    _logger.LogError("Invalid repository format: {Repository}", repository);
                    return null;
                }

                var owner = repoParts[0];
                var repo = repoParts[1];

                // Determine project and create issue
                var projectId = applicableRule.ProjectId ?? config.DefaultProjectId;
                var projectName = applicableRule.ProjectName ?? config.DefaultProjectName;

                var issueRequest = CreateIssueRequest(vulnerability, projectName);
                
                var issue = await _gitHubAppService.CreateIssueAsync(installation.InstallationId, owner, repo, issueRequest);
                
                // Save record of created work item to prevent duplicates
                var createdWorkItem = new CreatedWorkItem
                {
                    UserId = userId,
                    VulnerabilityId = vulnerability.Id,
                    VulnerabilityType = vulnerability.Type.ToString(),
                    Repository = repository,
                    GitHubIssueId = issue.Id,
                    GitHubIssueNumber = issue.Number,
                    GitHubIssueNodeId = issue.NodeId,
                    GitHubIssueUrl = issue.HtmlUrl,
                    IsActive = true
                };
                
                await _userService.SaveCreatedWorkItemAsync(createdWorkItem);
                
                _logger.LogInformation("Created work item {IssueNumber} for vulnerability {VulnId} in {Repository}", 
                    issue.Number, vulnerability.Id, repository);

                // If project is specified, add issue to project
                if (projectId.HasValue && !string.IsNullOrEmpty(projectName))
                {
                    // Find the project by ID to get its NodeId
                    var projects = await _gitHubAppService.GetOrganizationProjectsAsync(installation.InstallationId, owner);
                    var repoProjects = await _gitHubAppService.GetRepositoryProjectsAsync(installation.InstallationId, owner, repo);
                    projects.AddRange(repoProjects);
                    
                    var targetProject = projects.FirstOrDefault(p => p.Id == projectId.Value);
                    if (targetProject != null && !string.IsNullOrEmpty(targetProject.NodeId))
                    {
                        var added = await _gitHubAppService.AddIssueToProjectAsync(
                            installation.InstallationId, 
                            targetProject.NodeId, 
                            issue.NodeId);
                            
                        if (added)
                        {
                            _logger.LogInformation("Added issue {IssueNumber} to project {ProjectName}", 
                                issue.Number, projectName);
                        }
                        else
                        {
                            _logger.LogWarning("Failed to add issue {IssueNumber} to project {ProjectName}", 
                                issue.Number, projectName);
                        }
                    }
                    else
                    {
                        _logger.LogWarning("Project {ProjectName} (ID: {ProjectId}) not found for issue {IssueNumber}", 
                            projectName, projectId, issue.Number);
                    }
                }

                return issue;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create work item for vulnerability {VulnId}", vulnerability.Id);
                return null;
            }
        }

        private WorkItemRule? FindApplicableRule(WorkItemConfiguration config, VulnerabilityBase vulnerability)
        {
            return config.Rules
                .Where(r => r.IsEnabled)
                .Where(r => vulnerability.Severity <= r.MinimumSeverity) // Critical=0, High=1, etc.
                .Where(r => r.VulnerabilityTypes == null || r.VulnerabilityTypes.Contains(vulnerability.Type))
                .OrderBy(r => r.MinimumSeverity) // Most restrictive first
                .FirstOrDefault();
        }

        private CreateIssueRequest CreateIssueRequest(VulnerabilityBase vulnerability, string? projectName)
        {
            var title = $"[Security] {vulnerability.Title}";
            
            var bodyBuilder = new StringBuilder();
            bodyBuilder.AppendLine($"## Security Vulnerability Report");
            bodyBuilder.AppendLine();
            bodyBuilder.AppendLine($"**Severity:** {vulnerability.Severity}");
            bodyBuilder.AppendLine($"**Type:** {vulnerability.Type}");
            bodyBuilder.AppendLine($"**Asset:** {vulnerability.AssetName}");
            bodyBuilder.AppendLine($"**Detected:** {vulnerability.DetectedAt:yyyy-MM-dd HH:mm} UTC");
            bodyBuilder.AppendLine();
            bodyBuilder.AppendLine($"### Description");
            bodyBuilder.AppendLine(vulnerability.Description);
            
            if (!string.IsNullOrEmpty(vulnerability.FixGuidance))
            {
                bodyBuilder.AppendLine();
                bodyBuilder.AppendLine($"### Fix Guidance");
                bodyBuilder.AppendLine(vulnerability.FixGuidance);
            }

            // Add type-specific information
            switch (vulnerability)
            {
                case DependencyVulnerability depVuln:
                    bodyBuilder.AppendLine();
                    bodyBuilder.AppendLine($"### Dependency Information");
                    bodyBuilder.AppendLine($"**Package:** {depVuln.PackageName}");
                    bodyBuilder.AppendLine($"**Version:** {depVuln.Version}");
                    if (!string.IsNullOrEmpty(depVuln.FixedVersion))
                    {
                        bodyBuilder.AppendLine($"**Fixed in Version:** {depVuln.FixedVersion}");
                    }
                    bodyBuilder.AppendLine($"**File:** {depVuln.FilePath}");
                    break;
                    
                case SecretVulnerability secretVuln:
                    bodyBuilder.AppendLine();
                    bodyBuilder.AppendLine($"### Secret Information");
                    bodyBuilder.AppendLine($"**Secret Type:** {secretVuln.SecretType}");
                    bodyBuilder.AppendLine($"**File:** {secretVuln.FilePath}");
                    bodyBuilder.AppendLine($"**Line:** {secretVuln.LineNumber}");
                    bodyBuilder.AppendLine($"**Active:** {secretVuln.IsActive}");
                    break;
                    
                case CodeVulnerability codeVuln:
                    bodyBuilder.AppendLine();
                    bodyBuilder.AppendLine($"### Code Vulnerability Information");
                    bodyBuilder.AppendLine($"**Rule:** {codeVuln.Rule}");
                    bodyBuilder.AppendLine($"**Category:** {codeVuln.Category}");
                    bodyBuilder.AppendLine($"**File:** {codeVuln.FilePath}");
                    bodyBuilder.AppendLine($"**Line:** {codeVuln.LineNumber}");
                    break;
                    
                case CloudVulnerability cloudVuln:
                    bodyBuilder.AppendLine();
                    bodyBuilder.AppendLine($"### Cloud Resource Information");
                    bodyBuilder.AppendLine($"**Resource ID:** {cloudVuln.ResourceId}");
                    bodyBuilder.AppendLine($"**Resource Type:** {cloudVuln.ResourceType}");
                    bodyBuilder.AppendLine($"**Subscription:** {cloudVuln.SubscriptionId}");
                    bodyBuilder.AppendLine($"**Resource Group:** {cloudVuln.ResourceGroup}");
                    bodyBuilder.AppendLine($"**Location:** {cloudVuln.Location}");
                    bodyBuilder.AppendLine($"**Compliance Standard:** {cloudVuln.ComplianceStandard}");
                    break;
            }

            bodyBuilder.AppendLine();
            bodyBuilder.AppendLine($"---");
            bodyBuilder.AppendLine($"*This issue was automatically created by SecurityStats*");
            
            if (!string.IsNullOrEmpty(projectName))
            {
                bodyBuilder.AppendLine($"*Target Project: {projectName}*");
            }

            var labels = new List<string> { "security", vulnerability.Type.ToString().ToLower() };
            
            // Add severity label
            labels.Add($"severity-{vulnerability.Severity.ToString().ToLower()}");

            return new CreateIssueRequest
            {
                Title = title,
                Body = bodyBuilder.ToString(),
                Labels = labels
            };
        }

    }
}