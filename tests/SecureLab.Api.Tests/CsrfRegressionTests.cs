using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class CsrfRegressionTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static readonly string Url = $"/api/incidents/{DbSeeder.AliceIncidentId}";
    private static object Body(string title) => new { title, description = "REG-CSRF-01 local synthetic update" };

    private async Task<(string Title, string Description)> StateAsync()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var item = await db.Incidents.AsNoTracking().SingleAsync(i => i.Id == DbSeeder.AliceIncidentId);
        return (item.Title, item.Description);
    }

    [Fact]
    public async Task REG_CSRF_01_LoginCookie_RejectNoToken_KeepState_AcceptValidToken_ChangeState()
    {
        using var client = await factory.LoginAsync("alice", TestAuth.Password);
        var before = await StateAsync();
        client.DefaultRequestHeaders.Remove("X-SecureLab-CSRF");
        using (var denied = await client.PutAsJsonAsync(Url, Body("rejected")))
            Assert.Equal(HttpStatusCode.BadRequest, denied.StatusCode);
        Assert.Equal(before, await StateAsync());

        var token = await client.GetCsrfTokenAsync();
        client.DefaultRequestHeaders.Add("X-SecureLab-CSRF", token);
        var title = "csrf-ok-" + Guid.NewGuid().ToString("N");
        using (var accepted = await client.PutAsJsonAsync(Url, Body(title)))
            Assert.Equal(HttpStatusCode.NoContent, accepted.StatusCode);
        var after = await StateAsync();
        Assert.Equal(title, after.Title);
        Assert.NotEqual(before, after);
    }

    [Fact]
    public async Task REG_CSRF_02_InvalidToken_Fails_WithoutMutation()
    {
        using var client = await factory.LoginAsync("alice", TestAuth.Password);
        var before = await StateAsync();
        client.DefaultRequestHeaders.Remove("X-SecureLab-CSRF");
        client.DefaultRequestHeaders.Add("X-SecureLab-CSRF", "not-a-valid-token");
        using var response = await client.PutAsJsonAsync(Url, Body("invalid-token"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(before, await StateAsync());
    }

    [Fact]
    public async Task REG_CSRF_03_MismatchedCookieAndRequestToken_IsRejected()
    {
        using var alice = await factory.LoginAsync("alice", TestAuth.Password);
        using var bob = await factory.LoginAsync("bob", TestAuth.Password);
        var before = await StateAsync();
        var aliceToken = await alice.GetCsrfTokenAsync();
        bob.DefaultRequestHeaders.Remove("X-SecureLab-CSRF");
        bob.DefaultRequestHeaders.Add("X-SecureLab-CSRF", aliceToken);
        // Bob does not own the Alice incident; a 400 here proves token validation
        // precedes any resource authorization decision.
        using var response = await bob.PutAsJsonAsync(Url, Body("wrong-token-pair"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(before, await StateAsync());
    }
    [Fact]
    public async Task REG_CSRF_04_LogoutWithoutToken_DoesNotEndSession()
    {
        using var client = await factory.LoginAsync("alice", TestAuth.Password);
        client.DefaultRequestHeaders.Remove("X-SecureLab-CSRF");
        using (var denied = await client.PostAsync("/api/auth/logout", null))
            Assert.Equal(HttpStatusCode.BadRequest, denied.StatusCode);
        using var stillLoggedIn = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, stillLoggedIn.StatusCode);
        client.DefaultRequestHeaders.Add("X-SecureLab-CSRF", await client.GetCsrfTokenAsync());
        using (var logout = await client.PostAsync("/api/auth/logout", null))
            Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        using var loggedOut = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, loggedOut.StatusCode);
    }

    [Fact]
    public async Task REG_CSRF_05_CreateAndDelete_RequireToken()
    {
        using var client = await factory.LoginAsync("alice", TestAuth.Password);
        var title = "csrf-create-" + Guid.NewGuid().ToString("N");
        var body = new
        {
            title, description = "synthetic client mutation test", severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };
        client.DefaultRequestHeaders.Remove("X-SecureLab-CSRF");
        using (var denied = await client.PostAsJsonAsync("/api/incidents", body))
            Assert.Equal(HttpStatusCode.BadRequest, denied.StatusCode);
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            Assert.False(await db.Incidents.AnyAsync(x => x.Title == title));
        }
        client.DefaultRequestHeaders.Add("X-SecureLab-CSRF", await client.GetCsrfTokenAsync());
        using var created = await client.PostAsJsonAsync("/api/incidents", body);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        using var json = System.Text.Json.JsonDocument.Parse(await created.Content.ReadAsStringAsync());
        var id = json.RootElement.GetProperty("id").GetGuid();
        client.DefaultRequestHeaders.Remove("X-SecureLab-CSRF");
        using (var deniedDelete = await client.DeleteAsync($"/api/incidents/{id}"))
            Assert.Equal(HttpStatusCode.BadRequest, deniedDelete.StatusCode);
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            Assert.True(await db.Incidents.AnyAsync(x => x.Id == id));
        }
        client.DefaultRequestHeaders.Add("X-SecureLab-CSRF", await client.GetCsrfTokenAsync());
        using var deleted = await client.DeleteAsync($"/api/incidents/{id}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
    }


    [Fact]
    public async Task REG_CSRF_06_TriageWithoutToken_KeepsNewStatus()
    {
            using var alice = await factory.LoginAsync(
                "alice", TestAuth.Password);

            using var morgan = await factory.LoginAsync(
                "morgan", TestAuth.Password);

            var title = "csrf-triage-" +
                Guid.NewGuid().ToString("N");

            // Reporter створює власний інцидент.
            using var created = await alice.PostAsJsonAsync(
                "/api/incidents",
                new
                {
                    title,
                    description = "Synthetic triage test",
                    severity = "Low",
                    occurredAtUtc =
                        DateTimeOffset.UtcNow.AddMinutes(-10)
                });

            Assert.Equal(HttpStatusCode.Created, created.StatusCode);

            using var json = System.Text.Json.JsonDocument.Parse(
                await created.Content.ReadAsStringAsync());

            var id = json.RootElement
                .GetProperty("id")
                .GetGuid();

            // Analyst має право triage, але без CSRF-токена
            // сервер повинен відхилити запит.
            morgan.DefaultRequestHeaders.Remove(
                "X-SecureLab-CSRF");

            using (var denied = await morgan.PostAsync(
                $"/api/incidents/{id}/triage", null))
            {
                Assert.Equal(
                    HttpStatusCode.BadRequest,
                    denied.StatusCode);
            }

            // Після відмови статус залишається New.
            await using (var scope =
                factory.Services.CreateAsyncScope())
            {
                var db = scope.ServiceProvider
                    .GetRequiredService<SecureLabDbContext>();

                var status = await db.Incidents
                    .Where(x => x.Id == id)
                    .Select(x => x.Status)
                    .SingleAsync();

                Assert.Equal(
                    SecureLab.Api.Data.Entities.IncidentStatus.New,
                    status);
            }

            // Той самий Analyst отримує валідний CSRF-токен.
            var token = await morgan.GetCsrfTokenAsync();

            morgan.DefaultRequestHeaders.Add(
                "X-SecureLab-CSRF", token);

            using var accepted = await morgan.PostAsync(
                $"/api/incidents/{id}/triage", null);

            Assert.Equal(
                HttpStatusCode.NoContent,
                accepted.StatusCode);

            // Перевірка позитивного результату.
            await using (var scope =
                factory.Services.CreateAsyncScope())
            {
                var db = scope.ServiceProvider
                    .GetRequiredService<SecureLabDbContext>();

                var status = await db.Incidents
                    .Where(x => x.Id == id)
                    .Select(x => x.Status)
                    .SingleAsync();

                Assert.Equal(
                    SecureLab.Api.Data.Entities.IncidentStatus.Triaged,
                    status);
            }
        }
}
