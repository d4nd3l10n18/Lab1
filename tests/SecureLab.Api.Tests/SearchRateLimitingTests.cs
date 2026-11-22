using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace SecureLab.Api.Tests;

public sealed class SearchRateLimitingTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const string Search = "/api/incidents/search?q=rl06";

    [Fact]
    public async Task RL_Search_Quota_IsolatedPartitions_Recover_AndOtherEndpointUnaffected()
    {
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, c) => c.AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["RateLimiting:Search:PermitLimit"] = "3",
                    ["RateLimiting:Search:WindowSeconds"] = "2"
                })));
        using var alice = await host.LoginAsync("alice", TestAuth.Password);
        using var bob = await host.LoginAsync("bob", TestAuth.Password);

        for (var i = 0; i < 3; i++)
        {
            using var allowed = await alice.GetAsync(Search);
            Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        }
        using (var blocked = await alice.GetAsync(Search))
            Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);

        using (var otherPartition = await bob.GetAsync(Search))
            Assert.Equal(HttpStatusCode.OK, otherPartition.StatusCode);
        using (var unrelated = await alice.GetAsync("/api/me"))
            Assert.Equal(HttpStatusCode.OK, unrelated.StatusCode);
        await Task.Delay(TimeSpan.FromSeconds(2.5));
        using var recovered = await alice.GetAsync(Search);
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
    }

    [Fact]
    public async Task RL_Search_Anonymous_DoesNotBypassAuthentication()
    {
        using var client = factory.CreateClient(TestAuth.Https());
        using var response = await client.GetAsync(Search);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
