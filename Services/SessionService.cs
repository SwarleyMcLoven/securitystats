using SecurityStats.Models;

namespace SecurityStats.Services
{
    public class SessionService
    {
        private readonly ILogger<SessionService> _logger;
        private readonly Dictionary<string, UserSession> _sessions = new();

        public SessionService(ILogger<SessionService> logger)
        {
            _logger = logger;
        }

        public async Task<UserSession> CreateSessionAsync(string userId)
        {
            var session = new UserSession
            {
                UserId = userId,
                SessionId = Guid.NewGuid().ToString(),
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddHours(24),
                IsActive = true
            };

            _sessions[session.SessionId] = session;
            _logger.LogInformation("Created session {SessionId} for user {UserId}", session.SessionId, userId);

            return await Task.FromResult(session);
        }

        public async Task<UserSession?> GetSessionAsync(string sessionId)
        {
            if (_sessions.TryGetValue(sessionId, out var session))
            {
                if (session.ExpiresAt > DateTime.UtcNow && session.IsActive)
                {
                    return await Task.FromResult(session);
                }
                else
                {
                    // Session expired, remove it
                    _sessions.Remove(sessionId);
                    _logger.LogInformation("Session {SessionId} expired and removed", sessionId);
                }
            }

            return await Task.FromResult<UserSession?>(null);
        }

        public async Task<bool> ValidateSessionAsync(string sessionId)
        {
            var session = await GetSessionAsync(sessionId);
            return session != null;
        }

        public async Task InvalidateSessionAsync(string sessionId)
        {
            if (_sessions.TryGetValue(sessionId, out var session))
            {
                session.IsActive = false;
                _sessions.Remove(sessionId);
                _logger.LogInformation("Invalidated session {SessionId}", sessionId);
            }

            await Task.CompletedTask;
        }

        public async Task<string> GetCurrentUserIdAsync(string sessionId)
        {
            var session = await GetSessionAsync(sessionId);
            return session?.UserId ?? "demo-user"; // Fallback for demo purposes
        }

        public async Task CleanupExpiredSessionsAsync()
        {
            var expiredSessions = _sessions.Where(kvp => kvp.Value.ExpiresAt <= DateTime.UtcNow || !kvp.Value.IsActive)
                                           .ToList();

            foreach (var expiredSession in expiredSessions)
            {
                _sessions.Remove(expiredSession.Key);
                _logger.LogInformation("Removed expired session {SessionId}", expiredSession.Key);
            }

            _logger.LogInformation("Cleaned up {Count} expired sessions", expiredSessions.Count);
            await Task.CompletedTask;
        }
    }
}