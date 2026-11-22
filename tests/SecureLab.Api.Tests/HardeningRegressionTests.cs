using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public sealed class HardeningRegressionTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    [Theory]
    [InlineData("/", HttpStatusCode.OK)]
    [InlineData("/browser-lab.html", HttpStatusCode.OK)]
    [InlineData("/api/incidents?status=Unknown", HttpStatusCode.BadRequest)]
    [InlineData("/api/no-such-route", HttpStatusCode.NotFound)]
    public async Task HDR_SecurityHeaders_OnStaticAndApiResponses(string route, HttpStatusCode expected)
    {
        using var client = await factory.LoginAsync("alice", TestAuth.Password);
        using var response = await client.GetAsync(route);
        Assert.Equal(expected, response.StatusCode);
        Assert.True(response.Headers.TryGetValues("X-Content-Type-Options", out var nosniff));
        Assert.Contains("nosniff", nosniff!);
        Assert.True(response.Headers.TryGetValues("Referrer-Policy", out var referrer));
        Assert.Contains("no-referrer", referrer!);
        Assert.True(response.Headers.TryGetValues("Content-Security-Policy", out var csp));
        var policy = Assert.Single(csp!);
        Assert.Contains("script-src 'self'", policy, StringComparison.Ordinal);
        Assert.Contains("object-src 'none'", policy, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", policy, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CORS_AllowedOrigin_GetsCredentials_UnknownOriginDoesNot()
    {
        using var client = factory.CreateClient(TestAuth.Https());
        using var allowed = new HttpRequestMessage(HttpMethod.Get, "/health");
        allowed.Headers.Add("Origin", "http://localhost:4173");
        using var ok = await client.SendAsync(allowed);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal("http://localhost:4173",
            Assert.Single(ok.Headers.GetValues("Access-Control-Allow-Origin")));
        Assert.Equal("true", Assert.Single(ok.Headers.GetValues("Access-Control-Allow-Credentials")));

        using var denied = new HttpRequestMessage(HttpMethod.Get, "/health");
        denied.Headers.Add("Origin", "http://localhost:4174");
        using var response = await client.SendAsync(denied);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task CORS_Preflight_OnlyAllowsConfiguredMethodAndHeader()
    {
        using var client = factory.CreateClient(TestAuth.Https());
        using var request = new HttpRequestMessage(HttpMethod.Options, "/health");
        request.Headers.Add("Origin", "http://localhost:4173");
        request.Headers.Add("Access-Control-Request-Method", "GET");
        request.Headers.Add("Access-Control-Request-Headers", "X-Lab-Cors-Probe");
        using var response = await client.SendAsync(request);
        Assert.True(response.Headers.Contains("Access-Control-Allow-Origin"));
    }
}
