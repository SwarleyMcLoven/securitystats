using SecurityStats.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json.Serialization;

namespace SecurityStats.Services
{
    public class GitHubAppService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<GitHubAppService> _logger;
        private readonly UserService _userService;
        private readonly IConfiguration _configuration;
        private readonly string _baseUrl = "https://api.github.com";

        public GitHubAppService(HttpClient httpClient, ILogger<GitHubAppService> logger, UserService userService, IConfiguration configuration)
        {
            _httpClient = httpClient;
            _logger = logger;
            _userService = userService;
            _configuration = configuration;
            
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "SecurityStats/1.0");
            _httpClient.DefaultRequestHeaders.Add("Accept", "application/vnd.github+json");
            _httpClient.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
        }

        public GitHubAppConfiguration GetAppConfiguration()
        {
            return new GitHubAppConfiguration
            {
                AppId = _configuration["GitHubApp:AppId"] ?? "",
                ClientId = _configuration["GitHubApp:ClientId"] ?? "",
                ClientSecret = _configuration["GitHubApp:ClientSecret"] ?? "",
                PrivateKeyPath = _configuration["GitHubApp:PrivateKeyPath"] ?? "",
                WebhookSecret = _configuration["GitHubApp:WebhookSecret"] ?? ""
            };
        }

        public bool IsConfigured()
        {
            var config = GetAppConfiguration();
            return !string.IsNullOrEmpty(config.AppId) && 
                   !string.IsNullOrEmpty(config.ClientId) && 
                   !string.IsNullOrEmpty(config.ClientSecret) && 
                   !string.IsNullOrEmpty(config.PrivateKeyPath) &&
                   File.Exists(config.PrivateKeyPath);
        }

        public async Task<string> GetInstallationUrlAsync()
        {
            if (!IsConfigured())
                throw new InvalidOperationException("GitHub App configuration not set");

            var config = GetAppConfiguration();
            return $"https://github.com/apps/{GetAppSlugFromId(config.AppId)}/installations/new";
        }

        public async Task<GitHubAppInstallation> ProcessInstallationByIdAsync(long installationId, string userId)
        {
            if (!IsConfigured())
                throw new InvalidOperationException("GitHub App configuration not set");

            var config = GetAppConfiguration();

            // Get installation details
            var installationDetails = await GetInstallationDetailsAsync(installationId);
            
            // Generate installation token
            var accessToken = await GenerateInstallationTokenAsync(installationId);
            
            // Get repositories for this installation
            var repositories = await GetInstallationRepositoriesAsync(installationId);

            var installation = new GitHubAppInstallation
            {
                InstallationId = installationId,
                AppId = config.AppId,
                OrganizationName = installationDetails.Account?.Login ?? "Unknown",
                AccountType = installationDetails.Account?.Type ?? "Unknown",
                AccountId = installationDetails.Account?.Id ?? 0,
                RepositorySelection = repositories.Select(r => r.FullName ?? "").ToArray(),
                AccessToken = accessToken,
                AccessTokenExpiresAt = DateTime.UtcNow.AddHours(1), // GitHub installation tokens expire in 1 hour
                IsActive = true,
                Status = InstallationStatus.Active,
                RepositoryCount = repositories.Count,
                AvatarUrl = installationDetails.Account?.AvatarUrl,
                InstallationUrl = $"https://github.com/settings/installations/{installationId}",
                LastSyncAt = DateTime.UtcNow
            };

            return await _userService.SaveGitHubInstallationAsync(userId, installation);
        }

        public async Task<List<GitHubRepository>> GetInstallationRepositoriesAsync(long installationId)
        {
            var token = await GenerateInstallationTokenAsync(installationId);
            
            var originalAuth = _httpClient.DefaultRequestHeaders.Authorization;
            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            try
            {
                var url = $"{_baseUrl}/installation/repositories";
                var response = await _httpClient.GetStringAsync(url);
                var result = JsonSerializer.Deserialize<InstallationRepositoriesResponse>(response, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                });

                return result?.Repositories?.Select(r => new GitHubRepository
                {
                    Name = r.Name ?? "",
                    FullName = r.FullName ?? "",
                    Url = r.HtmlUrl ?? "",
                    IsPrivate = r.Private,
                    LastUpdated = r.UpdatedAt
                }).ToList() ?? new List<GitHubRepository>();
            }
            finally
            {
                _httpClient.DefaultRequestHeaders.Authorization = originalAuth;
            }
        }

        public async Task RefreshInstallationTokenAsync(GitHubAppInstallation installation)
        {
            var newToken = await GenerateInstallationTokenAsync(installation.InstallationId);
            installation.AccessToken = newToken;
            installation.AccessTokenExpiresAt = DateTime.UtcNow.AddHours(1); // GitHub installation tokens expire in 1 hour
            
            await _userService.SaveGitHubInstallationAsync(installation.UserId, installation);
        }

        public async Task<List<GitHubProject>> GetOrganizationProjectsAsync(long installationId, string organization)
        {
            var token = await GenerateInstallationTokenAsync(installationId);
            
            var originalAuth = _httpClient.DefaultRequestHeaders.Authorization;
            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            try
            {
                var projects = new List<GitHubProject>();
                
                // Get organization projects using GraphQL
                try
                {
                    var query = new GraphQLQuery
                    {
                        Query = @"
                            query($organization: String!, $first: Int) {
                                organization(login: $organization) {
                                    projectsV2(first: $first) {
                                        nodes {
                                            id
                                            databaseId
                                            title
                                            number
                                        }
                                    }
                                }
                            }",
                        Variables = new
                        {
                            organization = organization,
                            first = 100
                        }
                    };

                    var response = await ExecuteGraphQLQueryAsync(query);
                    var data = JsonSerializer.Deserialize<GraphQLOrgProjectsResponse>(response, new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    });

                    if (data?.Data?.Organization?.ProjectsV2?.Nodes != null)
                    {
                        projects.AddRange(data.Data.Organization.ProjectsV2.Nodes.Select(p => new GitHubProject
                        {
                            Id = p.DatabaseId ?? 0,
                            NodeId = p.Id ?? "",
                            Name = p.Title ?? "",
                            Number = p.Number ?? 0,
                            Owner = organization,
                            IsOrganizationProject = true
                        }));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to fetch organization projects for {Organization}", organization);
                }

                return projects;
            }
            finally
            {
                _httpClient.DefaultRequestHeaders.Authorization = originalAuth;
            }
        }

        public async Task<List<GitHubProject>> GetRepositoryProjectsAsync(long installationId, string owner, string repo)
        {
            var token = await GenerateInstallationTokenAsync(installationId);
            
            var originalAuth = _httpClient.DefaultRequestHeaders.Authorization;
            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            try
            {
                var projects = new List<GitHubProject>();
                
                // Get repository projects using GraphQL
                try
                {
                    var query = new GraphQLQuery
                    {
                        Query = @"
                            query($owner: String!, $repo: String!, $first: Int) {
                                repository(owner: $owner, name: $repo) {
                                    projectsV2(first: $first) {
                                        nodes {
                                            id
                                            databaseId
                                            title
                                            number
                                        }
                                    }
                                }
                            }",
                        Variables = new
                        {
                            owner = owner,
                            repo = repo,
                            first = 100
                        }
                    };

                    var response = await ExecuteGraphQLQueryAsync(query);
                    var data = JsonSerializer.Deserialize<GraphQLRepoProjectsResponse>(response, new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    });

                    if (data?.Data?.Repository?.ProjectsV2?.Nodes != null)
                    {
                        projects.AddRange(data.Data.Repository.ProjectsV2.Nodes.Select(p => new GitHubProject
                        {
                            Id = p.DatabaseId ?? 0,
                            NodeId = p.Id ?? "",
                            Name = p.Title ?? "",
                            Number = p.Number ?? 0,
                            Owner = owner,
                            Repository = repo,
                            IsOrganizationProject = false
                        }));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to fetch repository projects for {Owner}/{Repo}", owner, repo);
                }

                return projects;
            }
            finally
            {
                _httpClient.DefaultRequestHeaders.Authorization = originalAuth;
            }
        }

        public async Task<GitHubIssue> CreateIssueAsync(long installationId, string owner, string repo, CreateIssueRequest request)
        {
            var token = await GenerateInstallationTokenAsync(installationId);
            
            var originalAuth = _httpClient.DefaultRequestHeaders.Authorization;
            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            try
            {
                var url = $"{_baseUrl}/repos/{owner}/{repo}/issues";
                var json = JsonSerializer.Serialize(request, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                });
                
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync(url, content);
                var responseContent = await response.Content.ReadAsStringAsync();
                
                if (!response.IsSuccessStatusCode)
                {
                    throw new InvalidOperationException($"Failed to create issue: {responseContent}");
                }

                var issueDto = JsonSerializer.Deserialize<GitHubIssueDto>(responseContent, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                });

                return new GitHubIssue
                {
                    Id = issueDto?.Id ?? 0,
                    NodeId = issueDto?.NodeId ?? "",
                    Number = issueDto?.Number ?? 0,
                    Title = issueDto?.Title ?? "",
                    Body = issueDto?.Body ?? "",
                    State = issueDto?.State ?? "",
                    HtmlUrl = issueDto?.HtmlUrl ?? "",
                    CreatedAt = issueDto?.CreatedAt ?? DateTime.UtcNow
                };
            }
            finally
            {
                _httpClient.DefaultRequestHeaders.Authorization = originalAuth;
            }
        }

        private async Task<string> GenerateInstallationTokenAsync(long installationId)
        {
            if (!IsConfigured())
                throw new InvalidOperationException("GitHub App configuration not set");

            var config = GetAppConfiguration();
            var privateKey = await ReadPrivateKeyAsync(config.PrivateKeyPath);
            var jwt = GenerateJWT(config.AppId, privateKey);
            
            var originalAuth = _httpClient.DefaultRequestHeaders.Authorization;
            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

            try
            {
                var url = $"{_baseUrl}/app/installations/{installationId}/access_tokens";
                var response = await _httpClient.PostAsync(url, new StringContent("{}", Encoding.UTF8, "application/json"));
                var content = await response.Content.ReadAsStringAsync();
                
                if (!response.IsSuccessStatusCode)
                {
                    throw new InvalidOperationException($"Failed to generate installation token: {content}");
                }

                var tokenResponse = JsonSerializer.Deserialize<AccessTokenResponse>(content, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                });

                return tokenResponse?.Token ?? throw new InvalidOperationException("No token returned from GitHub");
            }
            finally
            {
                _httpClient.DefaultRequestHeaders.Authorization = originalAuth;
            }
        }


        private async Task<InstallationDetails> GetInstallationDetailsAsync(long installationId)
        {
            if (!IsConfigured())
                throw new InvalidOperationException("GitHub App configuration not set");

            var config = GetAppConfiguration();
            var privateKey = await ReadPrivateKeyAsync(config.PrivateKeyPath);
            var jwt = GenerateJWT(config.AppId, privateKey);
            
            var originalAuth = _httpClient.DefaultRequestHeaders.Authorization;
            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

            try
            {
                var url = $"{_baseUrl}/app/installations/{installationId}";
                var response = await _httpClient.GetStringAsync(url);
                
                return JsonSerializer.Deserialize<InstallationDetails>(response, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                }) ?? new InstallationDetails();
            }
            finally
            {
                _httpClient.DefaultRequestHeaders.Authorization = originalAuth;
            }
        }

        //private string GenerateJWT(string appId, string privateKey)
        //{
        //    var rsa = RSA.Create();
        //    rsa.ImportFromPem(privateKey);

        //    var securityKey = new RsaSecurityKey(rsa);
        //    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

        //    var now = DateTimeOffset.UtcNow;
        //    var claims = new[]
        //    {
        //        new Claim("iss", appId),
        //        new Claim("iat", now.ToUnixTimeSeconds().ToString()),
        //        new Claim("exp", now.AddMinutes(10).ToUnixTimeSeconds().ToString())
        //    };

        //    var token = new JwtSecurityToken(
        //        claims: claims,
        //        signingCredentials: credentials
        //    );

        //    return new JwtSecurityTokenHandler().WriteToken(token);
        //}

        private string GenerateJWT(string appId, string privateKey)
        {
            // JWT parts
            var header = new { alg = "RS256", typ = "JWT" };
            var now = DateTimeOffset.UtcNow;
            var payload = new
            {
                // Issued at time
                iat = now.ToUnixTimeSeconds(),
                // JWT expiration time (10 minutes maximum)
                exp = now.AddMinutes(9).ToUnixTimeSeconds(),
                // GitHub App's identifier
                iss = appId
            };

            // Encode header and payload
            var headerJson = System.Text.Json.JsonSerializer.Serialize(header);
            var payloadJson = System.Text.Json.JsonSerializer.Serialize(payload);
            var headerBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
            var payloadBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            var toSign = $"{headerBase64}.{payloadBase64}";

            // Create signature
            var signature = SignData(toSign, privateKey);
            var signatureBase64 = Base64UrlEncode(signature);

            // Combine to form JWT
            return $"{toSign}.{signatureBase64}";
        }

        private byte[] SignData(string data, string privateKey)
        {
            using var rsa = RSA.Create();

            try
            {
                rsa.ImportFromPem(privateKey);

                return rsa.SignData(
                    Encoding.UTF8.GetBytes(data),
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error signing data with private key");
                throw;
            }
        }

        private string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
        }



        private async Task<string> ReadPrivateKeyAsync(string privateKeyPath)
        {
            if (!File.Exists(privateKeyPath))
            {
                throw new FileNotFoundException($"Private key file not found at: {privateKeyPath}");
            }

            try
            {
                return await File.ReadAllTextAsync(privateKeyPath);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to read private key file: {ex.Message}", ex);
            }
        }

        private string GetAppSlugFromId(string appId)
        {
            // In a real implementation, you'd need to map the app ID to the app slug
            // For now, return a placeholder that users need to replace
            return "prosperity-security-posture";
        }

        private async Task<string> ExecuteGraphQLQueryAsync(GraphQLQuery query)
        {
            var graphqlUrl = "https://api.github.com/graphql";
            var json = JsonSerializer.Serialize(query, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
            
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync(graphqlUrl, content);
            var responseContent = await response.Content.ReadAsStringAsync();
            
            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException($"GraphQL query failed: {responseContent}");
            }

            return responseContent;
        }

        public async Task<bool> AddIssueToProjectAsync(long installationId, string projectNodeId, string issueNodeId)
        {
            var token = await GenerateInstallationTokenAsync(installationId);
            
            var originalAuth = _httpClient.DefaultRequestHeaders.Authorization;
            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            try
            {
                var mutation = new GraphQLQuery
                {
                    Query = @"
                        mutation($projectId: ID!, $contentId: ID!) {
                            addProjectV2ItemById(input: {
                                projectId: $projectId
                                contentId: $contentId
                            }) {
                                item {
                                    id
                                }
                            }
                        }",
                    Variables = new
                    {
                        projectId = projectNodeId,
                        contentId = issueNodeId
                    }
                };

                var response = await ExecuteGraphQLQueryAsync(mutation);
                var data = JsonSerializer.Deserialize<GraphQLAddItemResponse>(response, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });

                return data?.Data?.AddProjectV2ItemById?.Item?.Id != null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to add issue {IssueNodeId} to project {ProjectNodeId}", issueNodeId, projectNodeId);
                return false;
            }
            finally
            {
                _httpClient.DefaultRequestHeaders.Authorization = originalAuth;
            }
        }
    }


    public class AccessTokenResponse
    {
        public string Token { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
    }

    public class InstallationDetails
    {
        public InstallationAccount? Account { get; set; }
    }

    public class InstallationAccount
    {
        public string? Login { get; set; }
        public long Id { get; set; }
        public string? Type { get; set; }

        [JsonPropertyName("avatar_url")]
        public string? AvatarUrl { get; set; }
    }

    public class InstallationRepositoriesResponse
    {
        public List<GitHubRepoDto>? Repositories { get; set; }
    }

    public class GitHubProjectDto
    {
        public long Id { get; set; }
        [JsonPropertyName("node_id")]
        public string? NodeId { get; set; }
        public string? Name { get; set; }
        public int Number { get; set; }
    }

    public class GitHubIssueDto
    {
        public long Id { get; set; }
        [JsonPropertyName("node_id")]
        public string? NodeId { get; set; }
        public int Number { get; set; }
        public string? Title { get; set; }
        public string? Body { get; set; }
        public string? State { get; set; }
        [JsonPropertyName("html_url")]
        public string? HtmlUrl { get; set; }
        [JsonPropertyName("created_at")]
        public DateTime CreatedAt { get; set; }
    }

    public class CreateIssueRequest
    {
        public string Title { get; set; } = string.Empty;
        public string? Body { get; set; }
        public List<string>? Labels { get; set; }
    }

    // GraphQL DTOs
    public class GraphQLQuery
    {
        public string Query { get; set; } = string.Empty;
        public object? Variables { get; set; }
    }

    public class GraphQLOrgProjectsResponse
    {
        public GraphQLOrgProjectsData? Data { get; set; }
    }

    public class GraphQLOrgProjectsData
    {
        public GraphQLOrganization? Organization { get; set; }
    }

    public class GraphQLOrganization
    {
        public GraphQLProjectsV2? ProjectsV2 { get; set; }
    }

    public class GraphQLRepoProjectsResponse
    {
        public GraphQLRepoProjectsData? Data { get; set; }
    }

    public class GraphQLRepoProjectsData
    {
        public GraphQLRepository? Repository { get; set; }
    }

    public class GraphQLRepository
    {
        public GraphQLProjectsV2? ProjectsV2 { get; set; }
    }

    public class GraphQLProjectsV2
    {
        public List<GraphQLProjectNode>? Nodes { get; set; }
    }

    public class GraphQLProjectNode
    {
        public string? Id { get; set; }
        public long? DatabaseId { get; set; }
        public string? Title { get; set; }
        public int? Number { get; set; }
    }

    public class GraphQLAddItemResponse
    {
        public GraphQLAddItemData? Data { get; set; }
    }

    public class GraphQLAddItemData
    {
        public GraphQLAddProjectV2ItemById? AddProjectV2ItemById { get; set; }
    }

    public class GraphQLAddProjectV2ItemById
    {
        public GraphQLItem? Item { get; set; }
    }

    public class GraphQLItem
    {
        public string? Id { get; set; }
    }
}