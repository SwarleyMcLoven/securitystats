using Microsoft.EntityFrameworkCore;
using SecurityStats.Data;
using SecurityStats.Models;

namespace SecurityStats.Services
{
    public class UserService
    {
        private readonly SecurityStatsDbContext _context;
        private readonly ILogger<UserService> _logger;

        public UserService(SecurityStatsDbContext context, ILogger<UserService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<User> GetOrCreateUserAsync(string username)
        {
            var user = await _context.Users
                .Include(u => u.GitHubInstallations)
                .Include(u => u.AzureConfiguration)
                .Include(u => u.WorkItemConfiguration)
                    .ThenInclude(w => w.Rules)
                .FirstOrDefaultAsync(u => u.Username == username);

            if (user == null)
            {
                user = new User
                {
                    Username = username,
                    CreatedAt = DateTime.UtcNow,
                    LastLoginAt = DateTime.UtcNow
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();
                _logger.LogInformation("Created new user: {Username}", username);
            }
            else
            {
                user.LastLoginAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();
            }

            return user;
        }

        public async Task<GitHubAppInstallation?> GetActiveGitHubInstallationAsync(string userId)
        {
            return await _context.GitHubInstallations
                .FirstOrDefaultAsync(i => i.UserId == userId && i.IsActive);
        }

        public async Task<GitHubAppInstallation> SaveGitHubInstallationAsync(string userId, GitHubAppInstallation installation)
        {
            var existingInstallation = await _context.GitHubInstallations
                .FirstOrDefaultAsync(i => i.InstallationId == installation.InstallationId);

            if (existingInstallation != null)
            {
                existingInstallation.UserId = userId;
                existingInstallation.OrganizationName = installation.OrganizationName;
                existingInstallation.AccountType = installation.AccountType;
                existingInstallation.AccountId = installation.AccountId;
                existingInstallation.RepositorySelection = installation.RepositorySelection;
                existingInstallation.IsActive = true;
                existingInstallation.AccessToken = installation.AccessToken;
                existingInstallation.AccessTokenExpiresAt = installation.AccessTokenExpiresAt;
                existingInstallation.LastSyncAt = DateTime.UtcNow;
            }
            else
            {
                installation.UserId = userId;
                installation.InstalledAt = DateTime.UtcNow;
                _context.GitHubInstallations.Add(installation);
            }

            await _context.SaveChangesAsync();
            return existingInstallation ?? installation;
        }

        public async Task<AzureConfiguration?> GetAzureConfigurationAsync(string userId)
        {
            return await _context.AzureConfigurations
                .FirstOrDefaultAsync(c => c.UserId == userId && c.IsActive);
        }

        public async Task<AzureConfiguration> SaveAzureConfigurationAsync(string userId, AzureConfiguration config)
        {
            var existingConfig = await _context.AzureConfigurations
                .FirstOrDefaultAsync(c => c.UserId == userId);

            if (existingConfig != null)
            {
                existingConfig.SubscriptionId = config.SubscriptionId;
                existingConfig.TenantId = config.TenantId;
                existingConfig.ClientId = config.ClientId;
                existingConfig.ClientSecret = config.ClientSecret;
                existingConfig.IsActive = true;
                existingConfig.LastSyncAt = DateTime.UtcNow;
            }
            else
            {
                config.UserId = userId;
                config.ConfiguredAt = DateTime.UtcNow;
                _context.AzureConfigurations.Add(config);
            }

            await _context.SaveChangesAsync();
            return existingConfig ?? config;
        }

        public async Task<List<GitHubAppInstallation>> GetUserGitHubInstallationsAsync(string userId)
        {
            return await _context.GitHubInstallations
                .Where(i => i.UserId == userId)
                .OrderByDescending(i => i.InstalledAt)
                .ToListAsync();
        }

        public async Task<WorkItemConfiguration?> GetWorkItemConfigurationAsync(string userId)
        {
            return await _context.WorkItemConfigurations
                .Include(w => w.Rules)
                .FirstOrDefaultAsync(w => w.UserId == userId);
        }

        public async Task<WorkItemConfiguration> SaveWorkItemConfigurationAsync(WorkItemConfiguration config)
        {
            var existingConfig = await _context.WorkItemConfigurations
                .Include(w => w.Rules)
                .FirstOrDefaultAsync(w => w.UserId == config.UserId);

            if (existingConfig != null)
            {
                existingConfig.IsEnabled = config.IsEnabled;
                existingConfig.DefaultProjectId = config.DefaultProjectId;
                existingConfig.DefaultProjectName = config.DefaultProjectName;
                existingConfig.UpdatedAt = DateTime.UtcNow;

                // Remove existing rules that are not in the new configuration
                var rulesToRemove = existingConfig.Rules
                    .Where(er => !config.Rules.Any(nr => nr.Id == er.Id))
                    .ToList();
                
                foreach (var rule in rulesToRemove)
                {
                    _context.WorkItemRules.Remove(rule);
                }

                // Update existing rules and add new ones
                foreach (var rule in config.Rules)
                {
                    var existingRule = existingConfig.Rules.FirstOrDefault(r => r.Id == rule.Id);
                    if (existingRule != null)
                    {
                        existingRule.MinimumSeverity = rule.MinimumSeverity;
                        existingRule.VulnerabilityTypes = rule.VulnerabilityTypes;
                        existingRule.ProjectId = rule.ProjectId;
                        existingRule.ProjectName = rule.ProjectName;
                        existingRule.IsEnabled = rule.IsEnabled;
                    }
                    else
                    {
                        rule.WorkItemConfigurationId = existingConfig.Id;
                        existingConfig.Rules.Add(rule);
                    }
                }
            }
            else
            {
                config.CreatedAt = DateTime.UtcNow;
                config.UpdatedAt = DateTime.UtcNow;
                _context.WorkItemConfigurations.Add(config);
            }

            await _context.SaveChangesAsync();
            return existingConfig ?? config;
        }

        public async Task<CreatedWorkItem?> GetExistingWorkItemAsync(string userId, string vulnerabilityId, string repository, VulnerabilityType vulnerabilityType)
        {
            return await _context.CreatedWorkItems
                .FirstOrDefaultAsync(w => w.UserId == userId && 
                                         w.VulnerabilityId == vulnerabilityId && 
                                         w.Repository == repository && 
                                         w.VulnerabilityType == vulnerabilityType.ToString() &&
                                         w.IsActive);
        }

        public async Task<CreatedWorkItem> SaveCreatedWorkItemAsync(CreatedWorkItem workItem)
        {
            _context.CreatedWorkItems.Add(workItem);
            await _context.SaveChangesAsync();
            return workItem;
        }

        public async Task MarkWorkItemInactiveAsync(int workItemId)
        {
            var workItem = await _context.CreatedWorkItems.FindAsync(workItemId);
            if (workItem != null)
            {
                workItem.IsActive = false;
                await _context.SaveChangesAsync();
            }
        }
    }
}