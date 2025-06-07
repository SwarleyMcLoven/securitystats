using System.ComponentModel.DataAnnotations;
using SecurityStats.Models;

namespace SecurityStats.Models
{
    public class User
    {
        [Key]
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Username { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime LastLoginAt { get; set; } = DateTime.UtcNow;
        
        public List<GitHubAppInstallation> GitHubInstallations { get; set; } = new();
        public AzureConfiguration? AzureConfiguration { get; set; }
        public WorkItemConfiguration? WorkItemConfiguration { get; set; }
    }

    public class GitHubAppInstallation
    {
        [Key]
        public int Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public User User { get; set; } = null!;
        
        public long InstallationId { get; set; }
        public string AppId { get; set; } = string.Empty;
        public string OrganizationName { get; set; } = string.Empty;
        public string AccountType { get; set; } = string.Empty; // "User" or "Organization"
        public long AccountId { get; set; }
        public string[] RepositorySelection { get; set; } = Array.Empty<string>();
        public bool IsActive { get; set; } = true;
        public DateTime InstalledAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastSyncAt { get; set; }
        
        public string AccessToken { get; set; } = string.Empty;
        public DateTime AccessTokenExpiresAt { get; set; }
        
        // New fields for tracking installation status
        public InstallationStatus Status { get; set; } = InstallationStatus.Active;
        public string? StatusMessage { get; set; }
        public DateTime? LastStatusCheck { get; set; }
        public int RepositoryCount { get; set; }
        public string? AvatarUrl { get; set; }
        public string? InstallationUrl { get; set; }
    }

    public enum InstallationStatus
    {
        Active,
        Suspended,
        Removed,
        Error,
        TokenExpired,
        ConfigurationError
    }

    public class AzureConfiguration
    {
        [Key]
        public int Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public User User { get; set; } = null!;
        
        public string SubscriptionId { get; set; } = string.Empty;
        public string TenantId { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public bool IsActive { get; set; } = true;
        public DateTime ConfiguredAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastSyncAt { get; set; }
    }

    public class GitHubAppConfiguration
    {
        public string AppId { get; set; } = string.Empty;
        public string PrivateKeyPath { get; set; } = string.Empty;
        public string WebhookSecret { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
    }

    public class UserSession
    {
        public string UserId { get; set; } = string.Empty;
        public string SessionId { get; set; } = Guid.NewGuid().ToString();
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime ExpiresAt { get; set; } = DateTime.UtcNow.AddHours(24);
        public bool IsActive { get; set; } = true;
    }

    public class WorkItemConfiguration
    {
        [Key]
        public int Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public User User { get; set; } = null!;
        
        public bool IsEnabled { get; set; } = false;
        public List<WorkItemRule> Rules { get; set; } = new();
        public long? DefaultProjectId { get; set; }
        public string? DefaultProjectName { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }

    public class WorkItemRule
    {
        [Key]
        public int Id { get; set; }
        public int WorkItemConfigurationId { get; set; }
        public WorkItemConfiguration WorkItemConfiguration { get; set; } = null!;
        
        public VulnerabilitySeverity MinimumSeverity { get; set; }
        public VulnerabilityType[]? VulnerabilityTypes { get; set; }
        public long? ProjectId { get; set; }
        public string? ProjectName { get; set; }
        public bool IsEnabled { get; set; } = true;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    public class CreatedWorkItem
    {
        [Key]
        public int Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public User User { get; set; } = null!;
        
        public string VulnerabilityId { get; set; } = string.Empty;
        public string VulnerabilityType { get; set; } = string.Empty;
        public string Repository { get; set; } = string.Empty;
        public long GitHubIssueId { get; set; }
        public int GitHubIssueNumber { get; set; }
        public string GitHubIssueNodeId { get; set; } = string.Empty;
        public string GitHubIssueUrl { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public bool IsActive { get; set; } = true;
    }
}