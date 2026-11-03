using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace SecureLab.Api.Tests;

public sealed class Lab03RateLimitAndEventsTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const string LoginUrl = "/api/auth/login";

    [Fact]
    public async Task Login_Exceeding_Limit_Returns429_Recovers_AndEventsHaveNoCredentials()
    {
        var logs = new CapturingLoggerProvider();
        using var host = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, c) => c.AddInMemoryCollection(new Dictionary<string, string?>
            { ["RateLimiting:Login:PermitLimit"] = "3", ["RateLimiting:Login:WindowSeconds"] = "3" }));
            builder.ConfigureLogging(l =>
            {
                l.ClearProviders();
                l.AddProvider(logs);
            });
        });
        using var client = host.CreateClient(TestAuth.Https());
        var password = TestAuth.Password;
        var wrong = TestAuth.WrongPassword();

        for (var i = 0; i < 3; i++)
        {
            using var attempt = await client.PostAsJsonAsync(LoginUrl, new { userName = "alice", password = wrong });
            Assert.Equal(HttpStatusCode.Unauthorized, attempt.StatusCode);
        }

        using var blockedReal = await client.PostAsJsonAsync(LoginUrl, new { userName = "alice", password });
        using var blockedUnknown = await client.PostAsJsonAsync(LoginUrl,
            new { userName = "nouser" + Guid.NewGuid().ToString("N")[..6], password });
        Assert.Equal(HttpStatusCode.TooManyRequests, blockedReal.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, blockedUnknown.StatusCode);
        Assert.Equal(await ProblemShape.ReadAsync(blockedReal), await ProblemShape.ReadAsync(blockedUnknown));

        await Task.Delay(TimeSpan.FromSeconds(3.5));
        using var recovered = await client.PostAsJsonAsync(LoginUrl, new { userName = "alice", password });
        Assert.Equal(HttpStatusCode.NoContent, recovered.StatusCode);

        var messages = logs.Messages.ToArray();
        Assert.Contains(messages, m => m.Contains("Auth event login: result rate_limited"));
        Assert.Contains(messages, m => m.Contains("Auth event login: result failure"));
        Assert.Contains(messages, m => m.Contains("Auth event login: result success"));
        Assert.DoesNotContain(messages, m => m.Contains(password, StringComparison.Ordinal));
        Assert.DoesNotContain(messages, m => m.Contains(wrong, StringComparison.Ordinal));
    }
}