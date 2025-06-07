using SecurityStats.Models;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecurityStats.Services
{
    public class CommitAnalysisService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<CommitAnalysisService> _logger;
        private readonly UserService _userService;
        private readonly GitHubSecurityService _githubSecurityService;
        private readonly string _baseUrl = "https://api.github.com";

        public CommitAnalysisService(
            HttpClient httpClient,
            ILogger<CommitAnalysisService> logger,
            UserService userService,
            GitHubSecurityService githubSecurityService)
        {
            _httpClient = httpClient;
            _logger = logger;
            _userService = userService;
            _githubSecurityService = githubSecurityService;

            _httpClient.DefaultRequestHeaders.Add("User-Agent", "SecurityStats/1.0");
            _httpClient.DefaultRequestHeaders.Add("Accept", "application/vnd.github+json");
            _httpClient.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
        }

        public async Task<List<CommitAnalysis>> AnalyzeCommitsAsync(string userId, CommitAnalysisRequest request)
        {
            var results = new List<CommitAnalysis>();

            try
            {
                var user = await _userService.GetOrCreateUserAsync(userId);
                var installations = await _userService.GetUserGitHubInstallationsAsync(user.Id);
                installations = installations.Where(i => i.IsActive).ToList();

                // Filter installations based on request
                var installationsToProcess = request.InstallationId.HasValue
                    ? installations.Where(i => i.InstallationId == request.InstallationId.Value).ToList()
                    : installations;

                foreach (var installation in installationsToProcess)
                {
                    var repositories = await _githubSecurityService.GetRepositoriesAsync(installation.InstallationId);

                    // Filter repositories if specific repository requested
                    if (!string.IsNullOrEmpty(request.Repository))
                    {
                        repositories = repositories.Where(r => 
                            r.Name.Equals(request.Repository, StringComparison.OrdinalIgnoreCase) ||
                            r.FullName.Equals(request.Repository, StringComparison.OrdinalIgnoreCase)
                        ).ToList();
                    }

                    foreach (var repo in repositories)
                    {
                        try
                        {
                            var analysis = await AnalyzeRepositoryCommitsAsync(installation, repo, request);
                            if (analysis != null)
                            {
                                results.Add(analysis);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "Failed to analyze commits for repository {Repository}", repo.FullName);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing commits for user {UserId}", userId);
            }

            return results;
        }

        private async Task<CommitAnalysis?> AnalyzeRepositoryCommitsAsync(
            GitHubAppInstallation installation,
            GitHubRepository repository,
            CommitAnalysisRequest request)
        {
            try
            {
                var parts = repository.FullName.Split('/');
                if (parts.Length != 2) return null;

                var owner = parts[0];
                var repo = parts[1];

                // Get commits from the repository
                var commits = await GetCommitsAsync(installation, owner, repo, request.StartDate, request.EndDate);

                if (!commits.Any()) return null;

                // Get vulnerabilities for the repository
                var vulnerabilities = await GetRepositoryVulnerabilitiesAsync(installation, owner, repo);

                // Analyze commits and match with vulnerabilities
                var analyzedCommits = await AnalyzeCommitsForVulnerabilitiesAsync(commits, vulnerabilities);

                // Calculate author statistics
                var authorStats = CalculateAuthorStatistics(analyzedCommits);

                return new CommitAnalysis
                {
                    Repository = repo,
                    RepositoryFullName = repository.FullName,
                    TotalCommits = analyzedCommits.Count,
                    DistinctAuthors = analyzedCommits.GroupBy(c => c.AuthorEmail).Count(),
                    CommitsWithVulnerabilities = analyzedCommits.Count(c => c.HasVulnerabilities),
                    Commits = analyzedCommits.OrderByDescending(c => c.CommitDate).ToList(),
                    AuthorStatistics = authorStats,
                    AnalysisStartDate = request.StartDate,
                    AnalysisEndDate = request.EndDate,
                    LastAnalyzed = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing repository {Repository}", repository.FullName);
                return null;
            }
        }

        private async Task<List<CommitInfo>> GetCommitsAsync(
            GitHubAppInstallation installation,
            string owner,
            string repo,
            DateTime since,
            DateTime until)
        {
            var commits = new List<CommitInfo>();

            try
            {
                var originalAuth = _httpClient.DefaultRequestHeaders.Authorization;
                _httpClient.DefaultRequestHeaders.Authorization = 
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", installation.AccessToken);

                var sinceIso = since.ToString("yyyy-MM-ddTHH:mm:ssZ");
                var untilIso = until.ToString("yyyy-MM-ddTHH:mm:ssZ");
                var url = $"{_baseUrl}/repos/{owner}/{repo}/commits?since={sinceIso}&until={untilIso}&per_page=100";

                var response = await _httpClient.GetStringAsync(url);
                var commitDtos = JsonSerializer.Deserialize<List<GitHubCommitDto>>(response, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                });

                if (commitDtos != null)
                {
                    foreach (var commitDto in commitDtos)
                    {
                        var commitInfo = new CommitInfo
                        {
                            Sha = commitDto.Sha ?? "",
                            Message = commitDto.Commit?.Message ?? "",
                            AuthorName = commitDto.Commit?.Author?.Name ?? "",
                            AuthorEmail = commitDto.Commit?.Author?.Email ?? "",
                            CommitDate = commitDto.Commit?.Author?.Date ?? DateTime.MinValue,
                            Repository = $"{owner}/{repo}",
                            CommitUrl = commitDto.HtmlUrl ?? ""
                        };

                        // Get commit details for file changes
                        var commitDetails = await GetCommitDetailsAsync(installation, owner, repo, commitDto.Sha ?? "");
                        if (commitDetails != null)
                        {
                            commitInfo.ModifiedFiles = commitDetails.Files?.Select(f => f.Filename ?? "").ToList() ?? new List<string>();
                            commitInfo.AddedLines = commitDetails.Stats?.Additions ?? 0;
                            commitInfo.DeletedLines = commitDetails.Stats?.Deletions ?? 0;
                        }

                        commits.Add(commitInfo);
                    }
                }

                _httpClient.DefaultRequestHeaders.Authorization = originalAuth;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching commits for {Owner}/{Repo}", owner, repo);
            }

            return commits;
        }

        private async Task<GitHubCommitDetailsDto?> GetCommitDetailsAsync(
            GitHubAppInstallation installation,
            string owner,
            string repo,
            string sha)
        {
            try
            {
                var originalAuth = _httpClient.DefaultRequestHeaders.Authorization;
                _httpClient.DefaultRequestHeaders.Authorization = 
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", installation.AccessToken);

                var url = $"{_baseUrl}/repos/{owner}/{repo}/commits/{sha}";
                var response = await _httpClient.GetStringAsync(url);

                var commitDetails = JsonSerializer.Deserialize<GitHubCommitDetailsDto>(response, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                });

                _httpClient.DefaultRequestHeaders.Authorization = originalAuth;
                return commitDetails;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error fetching commit details for {Sha}", sha);
                return null;
            }
        }

        private async Task<List<VulnerabilityBase>> GetRepositoryVulnerabilitiesAsync(
            GitHubAppInstallation installation,
            string owner,
            string repo)
        {
            var vulnerabilities = new List<VulnerabilityBase>();

            try
            {
                var depVulns = await _githubSecurityService.GetDependencyVulnerabilitiesAsync(installation, owner, repo);
                var secretVulns = await _githubSecurityService.GetSecretVulnerabilitiesAsync(installation, owner, repo);
                var codeVulns = await _githubSecurityService.GetCodeVulnerabilitiesAsync(installation, owner, repo);

                vulnerabilities.AddRange(depVulns);
                vulnerabilities.AddRange(secretVulns);
                vulnerabilities.AddRange(codeVulns);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error fetching vulnerabilities for {Owner}/{Repo}", owner, repo);
            }

            return vulnerabilities;
        }

        private async Task<List<CommitInfo>> AnalyzeCommitsForVulnerabilitiesAsync(
            List<CommitInfo> commits,
            List<VulnerabilityBase> vulnerabilities)
        {
            foreach (var commit in commits)
            {
                var matches = new List<VulnerabilityMatch>();

                foreach (var vuln in vulnerabilities)
                {
                    // Check for file path matches
                    var vulnFilePath = GetVulnerabilityFilePath(vuln);
                    if (!string.IsNullOrEmpty(vulnFilePath) && 
                        commit.ModifiedFiles.Any(f => f.Contains(vulnFilePath, StringComparison.OrdinalIgnoreCase)))
                    {
                        matches.Add(new VulnerabilityMatch
                        {
                            VulnerabilityId = vuln.Id,
                            Type = vuln.Type,
                            Severity = vuln.Severity,
                            Title = vuln.Title,
                            FilePath = vulnFilePath,
                            Reason = MatchReason.FilePathMatch,
                            Description = $"Commit modified file: {vulnFilePath}"
                        });
                    }

                    // Check for time-based correlation (vulnerabilities detected around commit time)
                    var timeDiff = Math.Abs((vuln.DetectedAt - commit.CommitDate).TotalHours);
                    if (timeDiff <= 24) // Within 24 hours
                    {
                        matches.Add(new VulnerabilityMatch
                        {
                            VulnerabilityId = vuln.Id,
                            Type = vuln.Type,
                            Severity = vuln.Severity,
                            Title = vuln.Title,
                            FilePath = vulnFilePath,
                            Reason = MatchReason.TimeBasedCorrelation,
                            Description = $"Vulnerability detected within 24 hours of commit"
                        });
                    }
                }

                commit.AssociatedVulnerabilities = matches;
                commit.HasVulnerabilities = matches.Any();
            }

            return commits;
        }

        private string GetVulnerabilityFilePath(VulnerabilityBase vulnerability)
        {
            return vulnerability switch
            {
                DependencyVulnerability dep => dep.FilePath,
                SecretVulnerability secret => secret.FilePath,
                CodeVulnerability code => code.FilePath,
                _ => ""
            };
        }

        private List<AuthorStats> CalculateAuthorStatistics(List<CommitInfo> commits)
        {
            return commits
                .GroupBy(c => new { c.AuthorName, c.AuthorEmail })
                .Select(g => new AuthorStats
                {
                    AuthorName = g.Key.AuthorName,
                    AuthorEmail = g.Key.AuthorEmail,
                    CommitCount = g.Count(),
                    CommitsWithVulnerabilities = g.Count(c => c.HasVulnerabilities),
                    FirstCommit = g.Min(c => c.CommitDate),
                    LastCommit = g.Max(c => c.CommitDate),
                    TotalLinesAdded = g.Sum(c => c.AddedLines),
                    TotalLinesDeleted = g.Sum(c => c.DeletedLines)
                })
                .OrderByDescending(a => a.CommitCount)
                .ToList();
        }
    }

    // DTOs for GitHub API responses
    public class GitHubCommitDto
    {
        public string? Sha { get; set; }
        public GitHubCommitDataDto? Commit { get; set; }
        [JsonPropertyName("html_url")]
        public string? HtmlUrl { get; set; }
    }

    public class GitHubCommitDataDto
    {
        public string? Message { get; set; }
        public GitHubAuthorDto? Author { get; set; }
    }

    public class GitHubAuthorDto
    {
        public string? Name { get; set; }
        public string? Email { get; set; }
        public DateTime Date { get; set; }
    }

    public class GitHubCommitDetailsDto
    {
        public GitHubCommitStatsDto? Stats { get; set; }
        public List<GitHubFileDto>? Files { get; set; }
    }

    public class GitHubCommitStatsDto
    {
        public int Additions { get; set; }
        public int Deletions { get; set; }
        public int Total { get; set; }
    }

    public class GitHubFileDto
    {
        public string? Filename { get; set; }
        public int Additions { get; set; }
        public int Deletions { get; set; }
        public int Changes { get; set; }
        public string? Status { get; set; }
    }
}