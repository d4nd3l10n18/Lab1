using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Scaffolding;
using SecureLab.Api.Security;

namespace SecureLab.Api.Tests;

public sealed class AuditEndpointRegressionTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private async Task<AuditIntegrityEvent[]> EventsAsync()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.AuditIntegrityEvents.AsNoTracking().OrderBy(x => x.SequenceNumber).ToArrayAsync();
    }

    [Fact]
    public async Task AUTH_SuccessAndFailure_AreAudited_WithoutPasswords()
    {
        using var client = factory.CreateClient(TestAuth.Https());
        var secret = TestAuth.Password;
        using (var denied = await client.PostAsJsonAsync("/api/auth/login", new
        {
            userName = "alice", password = TestAuth.WrongPassword()
        })) Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        using (var success = await client.PostAsJsonAsync("/api/auth/login", new
        {
            userName = "alice", password = secret
        })) Assert.Equal(HttpStatusCode.NoContent, success.StatusCode);

        var events = await EventsAsync();
        Assert.Contains(events, x => x.Action == "auth.login" && x.Outcome == "denied");
        Assert.Contains(events, x => x.Action == "auth.login" && x.Outcome == "success"
            && x.ActorUserId == DbSeeder.AliceId);
        foreach (var row in events)
        {
            Assert.DoesNotContain(secret, System.Text.Json.JsonSerializer.Serialize(row), StringComparison.Ordinal);
            Assert.False(string.IsNullOrWhiteSpace(row.TraceId));
        }
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        Assert.Equal(events.Length, (await scope.ServiceProvider.GetRequiredService<AuditIntegrity>().VerifyAsync()).Count);
    }

    [Fact]
    public async Task INCIDENT_UpdateAndDeniedTriage_AreRecorded_WithValidChain()
    {
        using var alice = await factory.LoginAsync("alice", TestAuth.Password);
        var newTitle = "audit-update-" + Guid.NewGuid().ToString("N");
        using (var updated = await alice.PutAsJsonAsync($"/api/incidents/{DbSeeder.AliceIncidentId}",
            new { title = newTitle, description = "Synthetic audit endpoint test" }))
            Assert.Equal(HttpStatusCode.NoContent, updated.StatusCode);

        // Analyst is allowed to read but not mutate a reporter-owned Incident.
        using var analyst = await factory.LoginAsync("morgan", TestAuth.Password);
        using (var denied = await analyst.PutAsJsonAsync($"/api/incidents/{DbSeeder.AliceIncidentId}",
            new { title = "denied", description = "no mutation" }))
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

        var events = await EventsAsync();
        Assert.Contains(events, e => e.Action == "incident.update" && e.Outcome == "success");
        Assert.Contains(events, e => e.Action == "incident.update" && e.Outcome == "denied");
        await using var scope = factory.Services.CreateAsyncScope();
        Assert.Equal(events.Length,
            (await scope.ServiceProvider.GetRequiredService<AuditIntegrity>().VerifyAsync()).Count);
    }
    [Fact]
    public async Task INCIDENT_Triage_Delete_AndLogout_AreAudited()
    {
        using var alice = await factory.LoginAsync("alice", TestAuth.Password);
        async Task<Guid> CreateAsync(string title)
        {
            using var response = await alice.PostAsJsonAsync("/api/incidents", new
            {
                title,
                description = "local synthetic record for audit",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
            });
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            using var doc = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return doc.RootElement.GetProperty("id").GetGuid();
        }

        var forTriage = await CreateAsync("audit-triage-" + Guid.NewGuid().ToString("N"));
        using var analyst = await factory.LoginAsync("morgan", TestAuth.Password);
        using (var triage = await analyst.PostAsync($"/api/incidents/{forTriage}/triage", null))
            Assert.Equal(HttpStatusCode.NoContent, triage.StatusCode);

        var forDelete = await CreateAsync("audit-delete-" + Guid.NewGuid().ToString("N"));
        using (var deleted = await alice.DeleteAsync($"/api/incidents/{forDelete}"))
            Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        using (var logout = await alice.PostAsync("/api/auth/logout", null))
            Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        var events = await EventsAsync();
        Assert.Contains(events, e => e.Action == "incident.triage" && e.Outcome == "success"
            && e.EntityId == forTriage.ToString("D"));
        Assert.Contains(events, e => e.Action == "incident.delete" && e.Outcome == "success"
            && e.EntityId == forDelete.ToString("D"));
        Assert.Contains(events, e => e.Action == "auth.logout" && e.Outcome == "success"
            && e.ActorUserId == DbSeeder.AliceId);
        await using var scope = factory.Services.CreateAsyncScope();
        Assert.Equal(events.Length,
            (await scope.ServiceProvider.GetRequiredService<AuditIntegrity>().VerifyAsync()).Count);
    }

}
