namespace SecurityStats.Models
{
    public class CommitAnalysis
    {
        public string Repository { get; set; } = string.Empty;
        public string RepositoryFullName { get; set; } = string.Empty;
        public int TotalCommits { get; set; }
        public int DistinctAuthors { get; set; }
        public int CommitsWithVulnerabilities { get; set; }
        public List<CommitInfo> Commits { get; set; } = new();
        public List<AuthorStats> AuthorStatistics { get; set; } = new();
        public DateTime AnalysisStartDate { get; set; }
        public DateTime AnalysisEndDate { get; set; }
        public DateTime LastAnalyzed { get; set; } = DateTime.UtcNow;
    }

    public class CommitInfo
    {
        public string Sha { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public string AuthorName { get; set; } = string.Empty;
        public string AuthorEmail { get; set; } = string.Empty;
        public DateTime CommitDate { get; set; }
        public string Repository { get; set; } = string.Empty;
        public List<string> ModifiedFiles { get; set; } = new();
        public int AddedLines { get; set; }
        public int DeletedLines { get; set; }
        public bool HasVulnerabilities { get; set; }
        public List<VulnerabilityMatch> AssociatedVulnerabilities { get; set; } = new();
        public string CommitUrl { get; set; } = string.Empty;
    }

    public class AuthorStats
    {
        public string AuthorName { get; set; } = string.Empty;
        public string AuthorEmail { get; set; } = string.Empty;
        public int CommitCount { get; set; }
        public int CommitsWithVulnerabilities { get; set; }
        public double VulnerabilityRate => CommitCount > 0 ? (double)CommitsWithVulnerabilities / CommitCount * 100 : 0;
        public DateTime FirstCommit { get; set; }
        public DateTime LastCommit { get; set; }
        public int TotalLinesAdded { get; set; }
        public int TotalLinesDeleted { get; set; }
    }

    public class VulnerabilityMatch
    {
        public string VulnerabilityId { get; set; } = string.Empty;
        public VulnerabilityType Type { get; set; }
        public VulnerabilitySeverity Severity { get; set; }
        public string Title { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public MatchReason Reason { get; set; }
        public string Description { get; set; } = string.Empty;
    }

    public enum MatchReason
    {
        FilePathMatch,
        TimeBasedCorrelation,
        ContentAnalysis,
        ManualAssociation
    }

    public class CommitAnalysisRequest
    {
        public long? InstallationId { get; set; }
        public string? Repository { get; set; }
        public int DaysBack { get; set; } = 14;
        public DateTime StartDate => DateTime.UtcNow.AddDays(-DaysBack);
        public DateTime EndDate => DateTime.UtcNow;
    }
}