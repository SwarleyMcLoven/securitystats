using Microsoft.EntityFrameworkCore;
using SecurityStats.Models;

namespace SecurityStats.Data
{
    public class SecurityStatsDbContext : DbContext
    {
        public SecurityStatsDbContext(DbContextOptions<SecurityStatsDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<GitHubAppInstallation> GitHubInstallations { get; set; }
        public DbSet<AzureConfiguration> AzureConfigurations { get; set; }
        public DbSet<WorkItemConfiguration> WorkItemConfigurations { get; set; }
        public DbSet<WorkItemRule> WorkItemRules { get; set; }
        public DbSet<CreatedWorkItem> CreatedWorkItems { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Username).IsRequired().HasMaxLength(100);
                entity.HasIndex(e => e.Username).IsUnique();
            });

            modelBuilder.Entity<GitHubAppInstallation>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.UserId).IsRequired();
                entity.Property(e => e.AppId).IsRequired().HasMaxLength(50);
                entity.Property(e => e.OrganizationName).HasMaxLength(100);
                entity.Property(e => e.AccountType).HasMaxLength(20);
                entity.Property(e => e.AccessToken).HasMaxLength(500);
                entity.Property(e => e.StatusMessage).HasMaxLength(500);
                entity.Property(e => e.AvatarUrl).HasMaxLength(500);
                entity.Property(e => e.InstallationUrl).HasMaxLength(500);
                
                entity.Property(e => e.RepositorySelection)
                    .HasConversion(
                        v => string.Join(',', v),
                        v => v.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    );

                entity.HasOne(e => e.User)
                    .WithMany(u => u.GitHubInstallations)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasIndex(e => e.InstallationId).IsUnique();
                entity.HasIndex(e => new { e.UserId, e.OrganizationName });
            });

            modelBuilder.Entity<AzureConfiguration>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.UserId).IsRequired();
                entity.Property(e => e.SubscriptionId).IsRequired().HasMaxLength(50);
                entity.Property(e => e.TenantId).IsRequired().HasMaxLength(50);
                entity.Property(e => e.ClientId).IsRequired().HasMaxLength(50);
                entity.Property(e => e.ClientSecret).IsRequired().HasMaxLength(500);

                entity.HasOne(e => e.User)
                    .WithOne(u => u.AzureConfiguration)
                    .HasForeignKey<AzureConfiguration>(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            modelBuilder.Entity<WorkItemConfiguration>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.UserId).IsRequired();
                entity.Property(e => e.DefaultProjectName).HasMaxLength(200);

                entity.HasOne(e => e.User)
                    .WithOne(u => u.WorkItemConfiguration)
                    .HasForeignKey<WorkItemConfiguration>(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            modelBuilder.Entity<WorkItemRule>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.WorkItemConfigurationId).IsRequired();
                entity.Property(e => e.ProjectName).HasMaxLength(200);
                
                entity.Property(e => e.VulnerabilityTypes)
                    .HasConversion(
                        v => v != null ? string.Join(',', v.Select(x => x.ToString())) : null,
                        v => !string.IsNullOrEmpty(v) ? v.Split(',', StringSplitOptions.RemoveEmptyEntries)
                            .Select(x => Enum.Parse<VulnerabilityType>(x)).ToArray() : null
                    );

                entity.HasOne(e => e.WorkItemConfiguration)
                    .WithMany(w => w.Rules)
                    .HasForeignKey(e => e.WorkItemConfigurationId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            modelBuilder.Entity<CreatedWorkItem>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.UserId).IsRequired();
                entity.Property(e => e.VulnerabilityId).IsRequired().HasMaxLength(100);
                entity.Property(e => e.VulnerabilityType).IsRequired().HasMaxLength(50);
                entity.Property(e => e.Repository).IsRequired().HasMaxLength(200);
                entity.Property(e => e.GitHubIssueNodeId).HasMaxLength(100);
                entity.Property(e => e.GitHubIssueUrl).HasMaxLength(500);

                entity.HasOne(e => e.User)
                    .WithMany()
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                // Create unique index to prevent duplicates
                entity.HasIndex(e => new { e.UserId, e.VulnerabilityId, e.Repository, e.VulnerabilityType })
                    .IsUnique()
                    .HasDatabaseName("IX_CreatedWorkItem_Unique");
            });
        }
    }
}