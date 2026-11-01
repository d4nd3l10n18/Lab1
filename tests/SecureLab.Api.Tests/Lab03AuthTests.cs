using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class Lab03AuthTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const string LoginUrl = "/api/auth/login";

    private HttpClient Anonymous() =>
        factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    // A-01
    [Fact]
    public async Task A01_AnonymousCreate_Returns401_NotRedirect_AndCreatesNothing()
    {
        var title = "A01-" + Guid.NewGuid().ToString("N");
        using var anonymous = Anonymous();
        using var response = await anonymous.PostAsJsonAsync("/api/incidents", new
        {
            title, description = "Анонімна спроба створення.", severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        Assert.False(await db.Incidents.AnyAsync(i => i.Title == title));
    }

    [Fact]
    public async Task A01_AnonymousMe_Returns401()
    {
        using var anonymous = Anonymous();
        using var response = await anonymous.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    // A-02
    [Fact]
    public async Task A02_LoginThenMe_ReturnsOnlyCurrentPrincipalSafeFields()
    {
        using var alice = await factory.LoginAsync("alice", TestAuth.Password);
        using var response = await alice.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        Assert.Equal(DbSeeder.AliceId, root.GetProperty("id").GetGuid());
        Assert.Equal("alice", root.GetProperty("userName").GetString());
        Assert.Contains("Reporter", root.GetProperty("roles").EnumerateArray().Select(r => r.GetString()!));
        // allowlist полів: жодних hash / stamp / email / password
        Assert.Equal(new[] { "id", "roles", "userName" },
            root.EnumerateObject().Select(p => p.Name).Order().ToArray());
    }

    // A-03
    [Fact]
    public async Task A03_ForeignDemoHeader_DoesNotChangeCurrentUser()
    {
        using var alice = await factory.LoginAsync("alice", TestAuth.Password);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());
        using var response = await alice.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(DbSeeder.AliceId, doc.RootElement.GetProperty("id").GetGuid());
        Assert.Equal("alice", doc.RootElement.GetProperty("userName").GetString());
    }

    [Fact]
    public async Task A03_DemoHeaderWithoutCookie_Returns401()
    {
        using var anonymous = Anonymous();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());
        using var response = await anonymous.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // A-06
    [Fact]
    public async Task A06_Logout_ThenProtectedRequest_Returns401()
    {
        using var alice = await factory.LoginAsync("alice", TestAuth.Password);
        using (var before = await alice.GetAsync("/api/me"))
            Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        using var logout = await alice.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        // Основна cookie видаляється; значення/заголовки у failure не друкуємо.
        var cleared = logout.Headers.GetValues("Set-Cookie")
            .Where(v => v.StartsWith(".AspNetCore.Identity.Application=;", StringComparison.Ordinal)).ToArray();
        Assert.True(cleared.Length == 1);

        using var after = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    // A-07
    [Fact]
    public async Task A07_UnknownUser_And_WrongPassword_GiveIdenticalExternalResult()
    {
        using var client = Anonymous();
        using var unknown = await client.PostAsJsonAsync(LoginUrl,
            new { userName = "nouser" + Guid.NewGuid().ToString("N")[..8], password = TestAuth.Password });
        using var wrong = await client.PostAsJsonAsync(LoginUrl,
            new { userName = "alice", password = TestAuth.WrongPassword() });

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(unknown.Content.Headers.ContentType?.MediaType, wrong.Content.Headers.ContentType?.MediaType);
        Assert.False(unknown.Headers.Contains("Set-Cookie"));
        Assert.False(wrong.Headers.Contains("Set-Cookie"));
        // type/title/status/detail однакові; traceId навмисно не порівнюємо
        Assert.Equal(await ProblemShape.ReadAsync(unknown), await ProblemShape.ReadAsync(wrong));
    }
}