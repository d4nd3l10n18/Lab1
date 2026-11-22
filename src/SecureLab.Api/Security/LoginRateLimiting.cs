
using System.Threading.RateLimiting;

namespace SecureLab.Api.Security;

public static class LoginRateLimiting
{
    public const string PolicyName = "login";

    public static void AddLoginRateLimiting(this WebApplicationBuilder builder)
    {
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode =
                StatusCodes.Status429TooManyRequests;

            options.OnRejected = (context, _) =>
            {
                var isLogin = context.HttpContext.Request.Path
                    .StartsWithSegments("/api/auth/login");
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger(isLogin ? "SecureLab.Auth" : "SecureLab.RateLimit");

                logger.LogWarning(
                    "Auth event {EventType}: result {Result}, at {OccurredAtUtc}, trace {TraceId}",
                    isLogin ? "login" : "incident.search",
                    "rate_limited",
                    DateTimeOffset.UtcNow,
                    context.HttpContext.TraceIdentifier);

                return ValueTask.CompletedTask;
            };

            // Login rate limiter
            options.AddPolicy(PolicyName, http =>
            {
                var cfg = http.RequestServices
                    .GetRequiredService<IConfiguration>()
                    .GetSection("RateLimiting:Login");

                var permit = cfg.GetValue("PermitLimit", 10);

                var window = TimeSpan.FromSeconds(
                    cfg.GetValue("WindowSeconds", 60));

                return RateLimitPartition.GetFixedWindowLimiter(
                    http.Connection.RemoteIpAddress?.ToString()
                        ?? "unknown",
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = permit,
                        Window = window,
                        QueueLimit = 0,
                        AutoReplenishment = true
                    });
            });

            // Search rate limiter
            options.AddPolicy("incident-search", http =>
            {
                var userId = http.User.FindFirst(
                    System.Security.Claims.ClaimTypes.NameIdentifier
                )?.Value;

                var partitionKey = userId ?? "anonymous";
                var cfg = http.RequestServices.GetRequiredService<IConfiguration>()
                    .GetSection("RateLimiting:Search");
                var permit = cfg.GetValue("PermitLimit", 3);
                var window = TimeSpan.FromSeconds(cfg.GetValue("WindowSeconds", 10));

                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: partitionKey,
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = permit,
                        Window = window,
                        QueueLimit = 0,
                        AutoReplenishment = true
                    });
            });
        });
    }
}
