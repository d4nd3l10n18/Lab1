
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
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("SecureLab.Auth");

                logger.LogWarning(
                    "Auth event {EventType}: result {Result}, at {OccurredAtUtc}, trace {TraceId}",
                    "login",
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

                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: partitionKey,
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 3,
                        Window = TimeSpan.FromSeconds(10),
                        QueueLimit = 0,
                        AutoReplenishment = true
                    });
            });
        });
    }
}
