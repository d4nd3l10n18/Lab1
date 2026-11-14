using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class Lab04AuthorizationTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static readonly Guid CommentOnBob = Guid.Parse("30000000-0000-0000-0000-000000000002");
    private static readonly Guid InternalComment = Guid.Parse("30000000-0000-0000-0000-000000000003");

    private Task<HttpClient> LoginAsync(string user) => factory.LoginAsync(user, TestAuth.Password);
    private static string NewTitle(string prefix) => $"{prefix}-{Guid.NewGuid():N}";

    private static object NewBody(string title) => new
    {
        title,
        description = "Штучний запис для перевірки авторизації.",
        severity = "Low",
        occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
    };

    private static async Task<Guid> CreateAsync(HttpClient client, string title)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", NewBody(title));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("id").GetGuid();
    }

    private async Task<Incident?> LoadAsync(Guid id, IServiceProvider? services = null)
    {
        await using var scope = (services ?? factory.Services).CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.Incidents.AsNoTracking().SingleOrDefaultAsync(i => i.Id == id);
    }

    [Theory]
    [InlineData("GET", "/api/incidents")]
    [InlineData("GET", "/api/incidents/20000000-0000-0000-0000-000000000001")]
    [InlineData("GET", "/api/incidents/search?q=x")]
    [InlineData("GET", "/api/incidents/severity-summary")]
    [InlineData("GET", "/api/incident-comments/30000000-0000-0000-0000-000000000001")]
    [InlineData("PUT", "/api/incidents/20000000-0000-0000-0000-000000000001")]
    [InlineData("DELETE", "/api/incidents/20000000-0000-0000-0000-000000000001")]
    [InlineData("POST", "/api/incidents/20000000-0000-0000-0000-000000000001/triage")]
    public async Task A01_Anonymous_Returns401_NotRedirect(string method, string url)
    {
        using var anonymous = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        using var request = new HttpRequestMessage(new HttpMethod(method), url);
        if (method == "PUT")
        {
            request.Content = JsonContent.Create(new { title = "x", description = "y" });
        }

        using var response = await anonymous.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.NotEqual("text/html", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task A02_Alice_ReadsOwnDetails_WithoutOwnerFields()
    {
        using var alice = await LoginAsync("alice");
        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(DbSeeder.AliceIncidentId, doc.RootElement.GetProperty("id").GetGuid());
        Assert.False(doc.RootElement.TryGetProperty("ownerUserId", out _));
    }

    [Fact]
    public async Task A03_Alice_ReadsBobDetails_Returns404_WithoutBobData()
    {
        using var alice = await LoginAsync("alice");
        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        var text = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("Невідома спроба входу", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Боб", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A03R_Morgan_Analyst_ReadsAliceDetails()
    {
        using var morgan = await LoginAsync("morgan");
        using var response = await morgan.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task A04_Alice_UpdateBob_Returns404_AndDoesNotChangeBobIncident()
    {
        var before = await LoadAsync(DbSeeder.BobIncidentId);
        using var alice = await LoginAsync("alice");

        using var response = await alice.PutAsJsonAsync(
            $"/api/incidents/{DbSeeder.BobIncidentId}",
            new { title = "hacked by alice", description = "hacked" });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        var after = await LoadAsync(DbSeeder.BobIncidentId);
        Assert.Equal(before!.Title, after!.Title);
        Assert.Equal(before.Description, after.Description);
        Assert.Equal(before.UpdatedAtUtc, after.UpdatedAtUtc);
    }

    [Fact]
    public async Task A04_Alice_DeleteBob_Returns404_AndBobIncidentStillExists()
    {
        using var alice = await LoginAsync("alice");

        using var response = await alice.DeleteAsync($"/api/incidents/{DbSeeder.BobIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.NotNull(await LoadAsync(DbSeeder.BobIncidentId));
    }

    [Fact]
    public async Task A04_Analyst_UpdateAndDeleteAlice_AreForbidden_AndStateUnchanged()
    {
        var before = await LoadAsync(DbSeeder.AliceIncidentId);
        using var morgan = await LoginAsync("morgan");

        using var put = await morgan.PutAsJsonAsync(
            $"/api/incidents/{DbSeeder.AliceIncidentId}", new { title = "x", description = "y" });
        using var delete = await morgan.DeleteAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.Forbidden, put.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, delete.StatusCode);
        var after = await LoadAsync(DbSeeder.AliceIncidentId);
        Assert.Equal(before!.Title, after!.Title);
    }

    [Fact]
    public async Task A04_Owner_DeleteNonNewIncident_IsForbidden_AndIncidentStays()
    {
        using var alice = await LoginAsync("alice");   // incident-1 має status Triaged

        using var response = await alice.DeleteAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.NotNull(await LoadAsync(DbSeeder.AliceIncidentId));
    }

    [Fact]
    public async Task Owner_CanDeleteOwnNewIncident()
    {
        var title = NewTitle("L4-DEL");
        try
        {
            using var alice = await LoginAsync("alice");
            var id = await CreateAsync(alice, title);

            using var response = await alice.DeleteAsync($"/api/incidents/{id}");

            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            Assert.Null(await LoadAsync(id));
        }
        finally { await TestDb.DeleteIncidentsAsync(factory.Services, title); }
    }

    [Fact]
    public async Task A05_List_AsAlice_ContainsOnlyAliceIncidents()
    {
        using var alice = await LoginAsync("alice");
        var list = await alice.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");

        Assert.NotNull(list);
        Assert.Contains(list, i => i.Id == DbSeeder.AliceIncidentId);
        Assert.DoesNotContain(list, i => i.Id == DbSeeder.BobIncidentId);
        Assert.DoesNotContain(list, i => i.Id == Guid.Parse("20000000-0000-0000-0000-000000000004"));
    }

    [Fact]
    public async Task A06_Reporter_Triage_IsForbidden_AndStatusStaysNew()
    {
        var title = NewTitle("L4-A06");
        try
        {
            using var alice = await LoginAsync("alice");
            var id = await CreateAsync(alice, title);

            using var response = await alice.PostAsync($"/api/incidents/{id}/triage", content: null);

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal(IncidentStatus.New, (await LoadAsync(id))!.Status);
        }
        finally { await TestDb.DeleteIncidentsAsync(factory.Services, title); }
    }

    [Fact]
    public async Task A07_Analyst_Triage_New_BecomesTriaged_AndWritesHistory_ThenSecondCallIs409()
    {
        var title = NewTitle("L4-A07");
        try
        {
            using var alice = await LoginAsync("alice");
            using var morgan = await LoginAsync("morgan");
            var id = await CreateAsync(alice, title);

            using var first = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);
            using var second = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);

            Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
            Assert.Equal(IncidentStatus.Triaged, (await LoadAsync(id))!.Status);

            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            Assert.True(await db.IncidentStatusHistory.AnyAsync(h =>
                h.IncidentId == id && h.ChangedByUserId == DbSeeder.MorganId
                && h.OldStatus == IncidentStatus.New && h.NewStatus == IncidentStatus.Triaged));
        }
        finally { await TestDb.DeleteIncidentsAsync(factory.Services, title); }
    }

    [Fact]
    public async Task A08a_ForgedOwnerStatusSeverityRole_AreIgnored_ContentIsUpdated()
    {
        var title = NewTitle("L4-A08");
        var edited = title + "-edited";
        try
        {
            using var alice = await LoginAsync("alice");
            var id = await CreateAsync(alice, title);

            using var response = await alice.PutAsJsonAsync($"/api/incidents/{id}", new
            {
                title = edited,
                description = "Оновлений опис.",
                ownerUserId = DbSeeder.BobId,
                status = "Resolved",
                severity = "Critical",
                role = "Administrator",
                isTransitionAllowed = true
            });

            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            var row = await LoadAsync(id);
            Assert.Equal(edited, row!.Title);                          // дозволений content змінився
            Assert.Equal(DbSeeder.AliceId, row.OwnerUserId);           // owner без змін
            Assert.Equal(IncidentStatus.New, row.Status);              // status без змін
            Assert.Equal(IncidentSeverity.Low, row.Severity);          // severity без змін
        }
        finally
        {
            await TestDb.DeleteIncidentsAsync(factory.Services, title);
            await TestDb.DeleteIncidentsAsync(factory.Services, edited);
        }
    }

    [Fact]
    public async Task A09_DeniedTriage_WritesSafeAuditEvent_WithSameTraceIdAsResponse()
    {
        var logs = new CapturingLoggerProvider();
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureLogging(l => { l.ClearProviders(); l.AddProvider(logs); }));
        var title = NewTitle("L4-A09");
        var password = TestAuth.Password;
        try
        {
            using var alice = host.CreateClient(TestAuth.Https());
            using (var login = await alice.PostAsJsonAsync(
                "/api/auth/login", new { userName = "alice", password }))
            {
                Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
            }

            var id = await CreateAsync(alice, title);
            using var response = await alice.PostAsync($"/api/incidents/{id}/triage", content: null);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var traceId = body.RootElement.GetProperty("traceId").GetString()!;

            var audit = Assert.Single(logs.Messages.ToArray(),
                m => m.StartsWith("SecureLab.Audit|authorization.denied", StringComparison.Ordinal));
            Assert.Contains($"subject={DbSeeder.AliceId}", audit);
            Assert.Contains("action=incident.triage", audit);
            Assert.Contains($"resource={id}", audit);
            Assert.Contains("result=denied", audit);
            Assert.Contains(traceId, audit);
            Assert.DoesNotContain(password, audit, StringComparison.Ordinal);
            Assert.DoesNotContain("cookie", audit, StringComparison.OrdinalIgnoreCase);
        }
        finally { await TestDb.DeleteIncidentsAsync(host.Services, title); }
    }

    [Fact]
    public async Task A10_ForeignAndUnknownId_AreIndistinguishable404()
    {
        using var alice = await LoginAsync("alice");

        using var foreign = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        using var unknown = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(unknown.StatusCode, foreign.StatusCode);
        Assert.Equal(
            unknown.Content.Headers.ContentType?.ToString(),
            foreign.Content.Headers.ContentType?.ToString());

        var foreignBody = (await foreign.Content.ReadFromJsonAsync<JsonObject>())!;
        var unknownBody = (await unknown.Content.ReadFromJsonAsync<JsonObject>())!;
        foreignBody.Remove("traceId"); foreignBody.Remove("requestId");
        unknownBody.Remove("traceId"); unknownBody.Remove("requestId");
        Assert.True(JsonNode.DeepEquals(unknownBody, foreignBody));
    }

    [Fact]
    public async Task A11_SeveritySummary_AsAlice_CountsOnlyAliceIncidents()
    {
        using var alice = await LoginAsync("alice");
        var summary = await alice.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
            "/api/incidents/severity-summary");

        Assert.NotNull(summary);
        Assert.DoesNotContain(summary, s => s.Severity == "High");     // High — лише інцидент Bob
        Assert.Equal(1, summary.Single(s => s.Severity == "Medium").Count);
        Assert.Equal(2, summary.Single(s => s.Severity == "Low").Count);
    }

    [Fact]
    public async Task A11_Search_AsAlice_DoesNotFindBobIncident_ButAnalystDoes()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");
        var url = "/api/incidents/search?q=" + Uri.EscapeDataString("O'Brien");

        var asAlice = await alice.GetFromJsonAsync<List<IncidentSearchItem>>(url);
        var asMorgan = await morgan.GetFromJsonAsync<List<IncidentSearchItem>>(url);

        Assert.Empty(asAlice!);
        Assert.Single(asMorgan!);
    }

    [Fact]
    public async Task A12_Alice_ReadsCommentOnBobIncident_Returns404()
    {
        using var alice = await LoginAsync("alice");
        using var response = await alice.GetAsync($"/api/incident-comments/{CommentOnBob}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task A12_Reporter_DoesNotSeeInternalComment_Directly_OrInDetails()
    {
        using var alice = await LoginAsync("alice");

        using var direct = await alice.GetAsync($"/api/incident-comments/{InternalComment}");
        var details = await alice.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, direct.StatusCode);
        Assert.DoesNotContain(details!.Comments, c => c.Id == InternalComment);
        Assert.DoesNotContain(details.Comments, c => c.Text.Contains("Внутрішня нотатка"));
    }

    [Fact]
    public async Task A12_Analyst_SeesInternalComment_Directly_AndInDetails()
    {
        using var morgan = await LoginAsync("morgan");

        using var direct = await morgan.GetAsync($"/api/incident-comments/{InternalComment}");
        var details = await morgan.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, direct.StatusCode);
        Assert.Contains(details!.Comments, c => c.Id == InternalComment);
    }
}