namespace SecurityStats.Models
{
    public enum VulnerabilityType
    {
        Dependency,
        Secret,
        Code,
        Cloud
    }

    public enum VulnerabilitySeverity
    {
        Critical,
        High,
        Medium,
        Low,
        Info
    }

    public class VulnerabilityBase
    {
        public string Id { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public VulnerabilitySeverity Severity { get; set; }
        public VulnerabilityType Type { get; set; }
        public DateTime DetectedAt { get; set; }
        public string AssetName { get; set; } = string.Empty;
        public string AssetType { get; set; } = string.Empty;
        public string? FixGuidance { get; set; }
        public bool IsFixed { get; set; }
    }

    public class DependencyVulnerability : VulnerabilityBase
    {
        public string PackageName { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string? FixedVersion { get; set; }
        public string Repository { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
    }

    public class SecretVulnerability : VulnerabilityBase
    {
        public string SecretType { get; set; } = string.Empty;
        public string Repository { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public int LineNumber { get; set; }
        public bool IsActive { get; set; }
    }

    public class CodeVulnerability : VulnerabilityBase
    {
        public string Repository { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public int LineNumber { get; set; }
        public string Rule { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
    }

    public class CloudVulnerability : VulnerabilityBase
    {
        public string ResourceId { get; set; } = string.Empty;
        public string ResourceType { get; set; } = string.Empty;
        public string SubscriptionId { get; set; } = string.Empty;
        public string ResourceGroup { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;
        public string ComplianceStandard { get; set; } = string.Empty;
    }

    public class SecuritySummary
    {
        public int TotalVulnerabilities { get; set; }
        public Dictionary<VulnerabilityType, int> VulnerabilitiesByType { get; set; } = new();
        public Dictionary<VulnerabilitySeverity, int> VulnerabilitiesBySeverity { get; set; } = new();
        public int FixedVulnerabilities { get; set; }
        public DateTime LastUpdated { get; set; }
    }

    public class GitHubRepository
    {
        public string Name { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string Url { get; set; } = string.Empty;
        public bool IsPrivate { get; set; }
        public DateTime LastUpdated { get; set; }
    }

    public class AzureResource
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string SubscriptionId { get; set; } = string.Empty;
        public string ResourceGroup { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;
    }

    public class GitHubProject
    {
        public long Id { get; set; }
        public string NodeId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public int Number { get; set; }
        public string Owner { get; set; } = string.Empty;
        public string? Repository { get; set; }
        public bool IsOrganizationProject { get; set; }
    }

    public class GitHubIssue
    {
        public long Id { get; set; }
        public string NodeId { get; set; } = string.Empty;
        public int Number { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Body { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
        public string HtmlUrl { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
    }
}