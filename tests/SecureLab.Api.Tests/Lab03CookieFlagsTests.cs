using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public sealed class Lab03CookieFlagsTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string[] AttributesOf(HttpResponseMessage response)
    {
        var matching = response.Headers.GetValues("Set-Cookie")
            .Where(v => v.StartsWith(".AspNetCore.Identity.Application=", StringComparison.Ordinal)).ToArray();
        Assert.True(matching.Length == 1);                       // кількість, не значення
        return matching[0].Split(';').Skip(1).Select(p => p.Trim().ToLowerInvariant()).ToArray();
    }

    [Fact]
    public async Task Login_OverHttps_HttpOnly_Secure_LaxSessionCookie()
    {
        using var client = factory.CreateClient(TestAuth.Https());
        using var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = TestAuth.Password });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        var attrs = AttributesOf(response);
        Assert.Contains("httponly", attrs);
        Assert.Contains("secure", attrs);
        Assert.Contains("samesite=lax", attrs);
        Assert.Contains("path=/", attrs);
        Assert.DoesNotContain(attrs, a => a.StartsWith("expires=") || a.StartsWith("max-age="));  // сеансова
    }

    [Fact]
    public async Task Login_OverPlainHttpInDevelopment_HasNoSecure_ButStillHttpOnly()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        using var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = TestAuth.Password });
        var attrs = AttributesOf(response);
        Assert.Contains("httponly", attrs);
        Assert.DoesNotContain("secure", attrs);   // SameAsRequest у Development: межа локального HTTP
    }
}