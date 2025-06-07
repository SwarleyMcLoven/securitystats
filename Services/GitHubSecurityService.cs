using SecurityStats.Models;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecurityStats.Services
{
    public class GitHubSecurityService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<GitHubSecurityService> _logger;
        private readonly UserService _userService;
        private readonly GitHubAppService _gitHubAppService;
        private readonly string _baseUrl = "https://api.github.com";

        public GitHubSecurityService(HttpClient httpClient, ILogger<GitHubSecurityService> logger, UserService userService, GitHubAppService gitHubAppService)
        {
            _httpClient = httpClient;
            _logger = logger;
            _userService = userService;
            _gitHubAppService = gitHubAppService;
            
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "SecurityStats/1.0");
            _httpClient.DefaultRequestHeaders.Add("Accept", "application/vnd.github+json");
            _httpClient.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
        }

        public async Task<List<GitHubRepository>> GetRepositoriesAsync(string userId)
        {
            try
            {
                var installation = await _userService.GetActiveGitHubInstallationAsync(userId);

                //var installations = await _userService.GetUserGitHubInstallationsAsync(userId);

                if (installation == null)
                {
                    _logger.LogWarning("No active GitHub installation found for user {UserId}", userId);
                    return new List<GitHubRepository>();
                }

                return await _gitHubAppService.GetInstallationRepositoriesAsync(installation.InstallationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching repositories from GitHub for user {UserId}", userId);
                return new List<GitHubRepository>();
            }
        }

        public async Task<List<GitHubRepository>> GetRepositoriesAsync(long installationId)
        {
            try
            {
                return await _gitHubAppService.GetInstallationRepositoriesAsync(installationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching repositories from GitHub for installation Id {InstallationId}", installationId);
                return new List<GitHubRepository>();
            }
        }

        public async Task<List<DependencyVulnerability>> GetDependencyVulnerabilitiesAsync(GitHubAppInstallation installation, string owner, string repo)
        {
            try
            {
                //var installation = await _userService.GetActiveGitHubInstallationAsync(userId);
                //if (installation == null)
                //{
                //    _logger.LogWarning("No active GitHub installation found for user {UserId}", userId);
                //    return new List<DependencyVulnerability>();
                //}

                await EnsureValidTokenAsync(installation);
                
                var originalAuth = _httpClient.DefaultRequestHeaders.Authorization;
                _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", installation.AccessToken);

                try
                {
                    var url = $"{_baseUrl}/repos/{owner}/{repo}/dependabot/alerts";
                    var response = await _httpClient.GetStringAsync(url);
                    var alerts = JsonSerializer.Deserialize<List<DependabotAlertDto>>(response, new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                    });

                    var vulnerabilities = new List<DependencyVulnerability>();

                    if (alerts != null)
                    {
                        foreach (var alert in alerts)
                        {
                            var vulnerability = new DependencyVulnerability
                            {
                                Id = alert.Number.ToString(),
                                Title = alert.SecurityAdvisory?.Summary ?? "Unknown vulnerability",
                                Description = alert.SecurityAdvisory?.Description ?? "No description available",
                                Severity = MapSeverity(alert.SecurityAdvisory?.Severity),
                                Type = VulnerabilityType.Dependency,
                                DetectedAt = alert.CreatedAt,
                                AssetName = repo,
                                AssetType = "GitHub Repository",
                                PackageName = alert.Dependency?.Package?.Name ?? "Unknown",
                                Version = alert.Dependency?.ManifestPath ?? "Unknown",
                                Repository = $"{owner}/{repo}",
                                FilePath = alert.Dependency?.ManifestPath ?? "Unknown",
                                IsFixed = alert.State == "fixed"
                            };

                            if (alert.SecurityVulnerability?.FirstPatchedVersion?.Identifier != null)
                            {
                                vulnerability.FixedVersion = alert.SecurityVulnerability.FirstPatchedVersion.Identifier;
                            }

                            vulnerabilities.Add(vulnerability);
                        }
                    }

                    return vulnerabilities;
                }
                finally
                {
                    _httpClient.DefaultRequestHeaders.Authorization = originalAuth;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching dependency vulnerabilities for {Owner}/{Repo}", owner, repo);
                return new List<DependencyVulnerability>();
            }
        }

        public async Task<List<SecretVulnerability>> GetSecretVulnerabilitiesAsync(GitHubAppInstallation installation, string owner, string repo)
        {
            try
            {
                //var installation = await _userService.GetActiveGitHubInstallationAsync(userId);
                //if (installation == null)
                //{
                //    _logger.LogWarning("No active GitHub installation found for user {UserId}", userId);
                //    return new List<SecretVulnerability>();
                //}

                await EnsureValidTokenAsync(installation);
                
                var originalAuth = _httpClient.DefaultRequestHeaders.Authorization;
                _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", installation.AccessToken);

                try
                {
                    var url = $"{_baseUrl}/repos/{owner}/{repo}/secret-scanning/alerts";
                    var response = await _httpClient.GetStringAsync(url);
                var alerts = JsonSerializer.Deserialize<List<SecretScanningAlertDto>>(response, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                });

                var vulnerabilities = new List<SecretVulnerability>();

                if (alerts != null)
                {
                    foreach (var alert in alerts)
                    {
                        var vulnerability = new SecretVulnerability
                        {
                            Id = alert.Number.ToString(),
                            Title = $"{alert.SecretType} detected",
                            Description = $"Secret of type {alert.SecretType} detected in repository",
                            Severity = VulnerabilitySeverity.High,
                            Type = VulnerabilityType.Secret,
                            DetectedAt = alert.CreatedAt ?? DateTime.MinValue,
                            AssetName = repo,
                            AssetType = "GitHub Repository",
                            SecretType = alert.SecretType ?? "Unknown",
                            Repository = $"{owner}/{repo}",
                            IsActive = alert.State == "open",
                            IsFixed = alert.State == "resolved"
                        };

                        if (alert.Locations?.Count > 0)
                        {
                            var location = alert.Locations.First();
                            vulnerability.FilePath = location.Details?.Path ?? "Unknown";
                            vulnerability.LineNumber = location.Details?.StartLine ?? 0;
                        }

                        vulnerabilities.Add(vulnerability);
                    }
                }

                    return vulnerabilities;
                }
                finally
                {
                    _httpClient.DefaultRequestHeaders.Authorization = originalAuth;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching secret vulnerabilities for {Owner}/{Repo}", owner, repo);
                return new List<SecretVulnerability>();
            }
        }

        public async Task<List<CodeVulnerability>> GetCodeVulnerabilitiesAsync(GitHubAppInstallation installation, string owner, string repo)
        {
            try
            {
                //var installation = await _userService.GetActiveGitHubInstallationAsync(userId);
                //if (installation == null)
                //{
                //    _logger.LogWarning("No active GitHub installation found for user {UserId}", userId);
                //    return new List<CodeVulnerability>();
                //}

                await EnsureValidTokenAsync(installation);
                
                var originalAuth = _httpClient.DefaultRequestHeaders.Authorization;
                _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", installation.AccessToken);

                try
                {
                    var url = $"{_baseUrl}/repos/{owner}/{repo}/code-scanning/alerts";
                    var response = await _httpClient.GetStringAsync(url);
                var alerts = JsonSerializer.Deserialize<List<CodeScanningAlertDto>>(response, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                });

                var vulnerabilities = new List<CodeVulnerability>();

                if (alerts != null)
                {
                    foreach (var alert in alerts)
                    {
                        var vulnerability = new CodeVulnerability
                        {
                            Id = alert.Number.ToString(),
                            Title = alert.Rule?.Description ?? "Code vulnerability",
                            Description = alert.MostRecentInstance?.Message?.Text ?? "No description available",
                            Severity = MapCodeScanSeverity(alert.Rule?.SecuritySeverityLevel),
                            Type = VulnerabilityType.Code,
                            DetectedAt = alert.CreatedAt,
                            AssetName = repo,
                            AssetType = "GitHub Repository",
                            Repository = $"{owner}/{repo}",
                            Rule = alert.Rule?.Id ?? "Unknown",
                            Category = alert.Rule?.Tags?.FirstOrDefault() ?? "Unknown",
                            IsFixed = alert.State == "fixed"
                        };

                        if (alert.MostRecentInstance?.Location != null)
                        {
                            vulnerability.FilePath = alert.MostRecentInstance.Location.Path ?? "Unknown";
                            vulnerability.LineNumber = alert.MostRecentInstance.Location.StartLine ?? 0;
                        }

                        vulnerabilities.Add(vulnerability);
                    }
                }

                    return vulnerabilities;
                }
                finally
                {
                    _httpClient.DefaultRequestHeaders.Authorization = originalAuth;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching code vulnerabilities for {Owner}/{Repo}", owner, repo);
                return new List<CodeVulnerability>();
            }
        }

        private async Task EnsureValidTokenAsync(GitHubAppInstallation installation)
        {
            if (DateTime.UtcNow >= installation.AccessTokenExpiresAt.AddMinutes(-5))
            {
                await _gitHubAppService.RefreshInstallationTokenAsync(installation);
            }
        }

        private static VulnerabilitySeverity MapSeverity(string? severity)
        {
            return severity?.ToLower() switch
            {
                "critical" => VulnerabilitySeverity.Critical,
                "high" => VulnerabilitySeverity.High,
                "medium" => VulnerabilitySeverity.Medium,
                "low" => VulnerabilitySeverity.Low,
                _ => VulnerabilitySeverity.Info
            };
        }

        private static VulnerabilitySeverity MapCodeScanSeverity(string? severity)
        {
            return severity?.ToLower() switch
            {
                "critical" => VulnerabilitySeverity.Critical,
                "high" => VulnerabilitySeverity.High,
                "medium" => VulnerabilitySeverity.Medium,
                "low" => VulnerabilitySeverity.Low,
                _ => VulnerabilitySeverity.Info
            };
        }
    }

    public class GitHubRepoDto
    {
        public string? Name { get; set; }
        [JsonPropertyName("full_name")]
        public string? FullName { get; set; }
        [JsonPropertyName("html_url")]
        public string? HtmlUrl { get; set; }
        public bool Private { get; set; }
        [JsonPropertyName("updated_at")]
        public DateTime UpdatedAt { get; set; }
    }

    public class DependabotAlertDto
    {
        public int Number { get; set; }
        public string? State { get; set; }
        [JsonPropertyName("created_at")]
        public DateTime CreatedAt { get; set; }
        public DependencyDto? Dependency { get; set; }
        [JsonPropertyName("security_advisory")]
        public SecurityAdvisoryDto? SecurityAdvisory { get; set; }
        [JsonPropertyName("security_vulnerability")]
        public SecurityVulnerabilityDto? SecurityVulnerability { get; set; }
    }

    public class DependencyDto
    {
        public PackageDto? Package { get; set; }
        [JsonPropertyName("manifest_path")]
        public string? ManifestPath { get; set; }
    }

    public class PackageDto
    {
        public string? Name { get; set; }
    }

    public class SecurityAdvisoryDto
    {
        public string? Summary { get; set; }
        public string? Description { get; set; }
        public string? Severity { get; set; }
    }

    public class SecurityVulnerabilityDto
    {
        [JsonPropertyName("first_patched_version")]
        public FirstPatchedVersionDto? FirstPatchedVersion { get; set; }
    }

    public class FirstPatchedVersionDto
    {
        public string? Identifier { get; set; }
    }

    public class SecretScanningAlertDto
    {
        public int Number { get; set; }
        public string? State { get; set; }
        [JsonPropertyName("secret_type")]
        public string? SecretType { get; set; }
        [JsonPropertyName("created_at")]
        public DateTime? CreatedAt { get; set; }
        public List<SecretLocationDto>? Locations { get; set; }
    }

    public class SecretLocationDto
    {
        public SecretLocationDetailsDto? Details { get; set; }
    }

    public class SecretLocationDetailsDto
    {
        public string? Path { get; set; }
        [JsonPropertyName("start_line")]
        public int StartLine { get; set; }
    }

    public class CodeScanningAlertDto
    {
        public int Number { get; set; }
        public string? State { get; set; }
        [JsonPropertyName("created_at")]
        public DateTime CreatedAt { get; set; }
        public CodeScanningRuleDto? Rule { get; set; }
        [JsonPropertyName("most_recent_instance")]
        public CodeScanningInstanceDto? MostRecentInstance { get; set; }
    }

    public class CodeScanningRuleDto
    {
        public string? Id { get; set; }
        public string? Description { get; set; }
        [JsonPropertyName("security_severity_level")]
        public string? SecuritySeverityLevel { get; set; }
        public List<string>? Tags { get; set; }
    }

    public class CodeScanningInstanceDto
    {
        public CodeScanningMessageDto? Message { get; set; }
        public CodeScanningLocationDto? Location { get; set; }
    }

    public class CodeScanningMessageDto
    {
        public string? Text { get; set; }
    }

    public class CodeScanningLocationDto
    {
        public string? Path { get; set; }
        [JsonPropertyName("start_line")]
        public int? StartLine { get; set; }
    }
}