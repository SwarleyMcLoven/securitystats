using Azure.Identity;
using Azure.ResourceManager.SecurityCenter;
using SecurityStats.Models;
using System.Text.Json;

namespace SecurityStats.Services
{
    public class AzureSecurityService
    {
        private readonly ILogger<AzureSecurityService> _logger;
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;

        public AzureSecurityService(IConfiguration configuration, ILogger<AzureSecurityService> logger, HttpClient httpClient)
        {
            _configuration = configuration;
            _logger = logger;
            _httpClient = httpClient;
        }

        public async Task<List<AzureResource>> GetAzureResourcesAsync()
        {
            try
            {
                var subscriptionId = _configuration["Azure:SubscriptionId"];
                if (string.IsNullOrEmpty(subscriptionId))
                {
                    throw new InvalidOperationException("Azure SubscriptionId is not configured.");
                }

                var credential = new DefaultAzureCredential();
                var token = await credential.GetTokenAsync(new Azure.Core.TokenRequestContext(new[] { "https://management.azure.com/.default" }));
                
                _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token.Token);

                var url = $"https://management.azure.com/subscriptions/{subscriptionId}/resources?api-version=2021-04-01";
                var response = await _httpClient.GetStringAsync(url);
                var resourcesResponse = JsonSerializer.Deserialize<AzureResourcesResponse>(response, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });

                return resourcesResponse?.Value?.Select(r => new AzureResource
                {
                    Id = r.Id,
                    Name = r.Name,
                    Type = r.Type,
                    SubscriptionId = subscriptionId,
                    ResourceGroup = ExtractResourceGroup(r.Id),
                    Location = r.Location
                }).ToList() ?? new List<AzureResource>();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching Azure resources");
                return new List<AzureResource>();
            }
        }

        public async Task<List<CloudVulnerability>> GetCloudVulnerabilitiesAsync()
        {
            try
            {
                var subscriptionId = _configuration["Azure:SubscriptionId"];
                if (string.IsNullOrEmpty(subscriptionId))
                {
                    throw new InvalidOperationException("Azure SubscriptionId is not configured.");
                }

                var credential = new DefaultAzureCredential();
                var token = await credential.GetTokenAsync(new Azure.Core.TokenRequestContext(new[] { "https://management.azure.com/.default" }));
                
                _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token.Token);

                var vulnerabilities = new List<CloudVulnerability>();

                var assessmentsUrl = $"https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01";
                var assessmentsResponse = await _httpClient.GetStringAsync(assessmentsUrl);
                var assessments = JsonSerializer.Deserialize<SecurityAssessmentsResponse>(assessmentsResponse, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });

                if (assessments?.Value != null)
                {
                    foreach (var assessment in assessments.Value)
                    {
                        if (assessment.Properties?.Status?.Code == "Unhealthy")
                        {
                            var vulnerability = new CloudVulnerability
                            {
                                Id = assessment.Id,
                                Title = assessment.Properties.DisplayName ?? "Unknown Issue",
                                Description = assessment.Properties.Description ?? "No description available",
                                Severity = MapAzureSeverity(assessment.Properties.Metadata?.Severity),
                                Type = VulnerabilityType.Cloud,
                                DetectedAt = DateTime.UtcNow,
                                AssetName = ExtractResourceName(assessment.Properties.ResourceDetails?.Id),
                                AssetType = "Azure Resource",
                                ResourceId = assessment.Properties.ResourceDetails?.Id ?? "Unknown",
                                ResourceType = ExtractResourceType(assessment.Properties.ResourceDetails?.Id),
                                SubscriptionId = subscriptionId,
                                ResourceGroup = ExtractResourceGroup(assessment.Properties.ResourceDetails?.Id),
                                Location = "Unknown",
                                ComplianceStandard = assessment.Properties.Metadata?.Categories?.FirstOrDefault() ?? "Security",
                                IsFixed = false
                            };

                            vulnerabilities.Add(vulnerability);
                        }
                    }
                }

                var alertsUrl = $"https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/alerts?api-version=2022-01-01";
                try
                {
                    var alertsResponse = await _httpClient.GetStringAsync(alertsUrl);
                    var alerts = JsonSerializer.Deserialize<SecurityAlertsResponse>(alertsResponse, new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    });

                    if (alerts?.Value != null)
                    {
                        foreach (var alert in alerts.Value)
                        {
                            var vulnerability = new CloudVulnerability
                            {
                                Id = alert.Id,
                                Title = alert.Properties?.AlertDisplayName ?? "Security Alert",
                                Description = alert.Properties?.Description ?? "No description available",
                                Severity = MapAzureSeverity(alert.Properties?.Severity),
                                Type = VulnerabilityType.Cloud,
                                DetectedAt = alert.Properties?.TimeGeneratedUtc ?? DateTime.UtcNow,
                                AssetName = ExtractResourceName(alert.Properties?.CompromisedEntity),
                                AssetType = "Azure Resource",
                                ResourceId = alert.Properties?.CompromisedEntity ?? "Unknown",
                                ResourceType = "Security Alert",
                                SubscriptionId = subscriptionId,
                                ResourceGroup = ExtractResourceGroup(alert.Properties?.CompromisedEntity),
                                Location = "Unknown",
                                ComplianceStandard = "Security Alert",
                                IsFixed = alert.Properties?.Status == "Resolved"
                            };

                            vulnerabilities.Add(vulnerability);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not fetch security alerts, continuing without them");
                }

                return vulnerabilities;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching cloud vulnerabilities from Azure");
                return new List<CloudVulnerability>();
            }
        }

        private static string ExtractResourceGroup(string? resourceId)
        {
            if (string.IsNullOrEmpty(resourceId)) return "Unknown";
            
            var parts = resourceId.Split('/');
            var rgIndex = Array.IndexOf(parts, "resourceGroups");
            return rgIndex >= 0 && rgIndex + 1 < parts.Length ? parts[rgIndex + 1] : "Unknown";
        }

        private static string ExtractResourceName(string? resourceId)
        {
            if (string.IsNullOrEmpty(resourceId)) return "Unknown";
            
            var parts = resourceId.Split('/');
            return parts.LastOrDefault() ?? "Unknown";
        }

        private static string ExtractResourceType(string? resourceId)
        {
            if (string.IsNullOrEmpty(resourceId)) return "Unknown";
            
            var parts = resourceId.Split('/');
            if (parts.Length >= 2)
            {
                var providerIndex = Array.FindIndex(parts, p => p.StartsWith("Microsoft."));
                if (providerIndex >= 0 && providerIndex + 1 < parts.Length)
                {
                    return $"{parts[providerIndex]}/{parts[providerIndex + 1]}";
                }
            }
            return "Unknown";
        }

        private static VulnerabilitySeverity MapAzureSeverity(string? severity)
        {
            return severity?.ToLower() switch
            {
                "critical" => VulnerabilitySeverity.Critical,
                "high" => VulnerabilitySeverity.High,
                "medium" => VulnerabilitySeverity.Medium,
                "low" => VulnerabilitySeverity.Low,
                "informational" => VulnerabilitySeverity.Info,
                _ => VulnerabilitySeverity.Medium
            };
        }
    }

    public class AzureResourcesResponse
    {
        public List<AzureResourceDto>? Value { get; set; }
    }

    public class AzureResourceDto
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;
    }

    public class SecurityAssessmentsResponse
    {
        public List<SecurityAssessment>? Value { get; set; }
    }

    public class SecurityAssessment
    {
        public string Id { get; set; } = string.Empty;
        public SecurityAssessmentProperties? Properties { get; set; }
    }

    public class SecurityAssessmentProperties
    {
        public string? DisplayName { get; set; }
        public string? Description { get; set; }
        public SecurityAssessmentStatus? Status { get; set; }
        public SecurityAssessmentResourceDetails? ResourceDetails { get; set; }
        public SecurityAssessmentMetadata? Metadata { get; set; }
    }

    public class SecurityAssessmentStatus
    {
        public string? Code { get; set; }
    }

    public class SecurityAssessmentResourceDetails
    {
        public string? Id { get; set; }
    }

    public class SecurityAssessmentMetadata
    {
        public string? Severity { get; set; }
        public List<string>? Categories { get; set; }
    }

    public class SecurityAlertsResponse
    {
        public List<SecurityAlert>? Value { get; set; }
    }

    public class SecurityAlert
    {
        public string Id { get; set; } = string.Empty;
        public SecurityAlertProperties? Properties { get; set; }
    }

    public class SecurityAlertProperties
    {
        public string? AlertDisplayName { get; set; }
        public string? Description { get; set; }
        public string? Severity { get; set; }
        public string? Status { get; set; }
        public string? CompromisedEntity { get; set; }
        public DateTime? TimeGeneratedUtc { get; set; }
    }
}