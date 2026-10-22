using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class Lab02ContractTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    private static string NewTitle(string prefix) => $"{prefix}-{Guid.NewGuid():N}";

    private static StringContent Json(string json) =>
        new(json, Encoding.UTF8, "application/json");

    private static object Body(string title, string severity = "Low",
        string description = "Штучний запис для регресійного тесту.", DateTimeOffset? occurred = null) =>
        new { title, description, severity, occurredAtUtc = occurred ?? DateTimeOffset.UtcNow.AddMinutes(-10) };

    private async Task CleanupAsync(string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
    }

    private static async Task AssertSafeProblemAsync(HttpResponseMessage response, string expectedErrorKey)
    {
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var text = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(text);
        Assert.True(doc.RootElement.TryGetProperty("title", out _));
        Assert.True(doc.RootElement.TryGetProperty("status", out _));
        if (expectedErrorKey != "")
            Assert.True(doc.RootElement.GetProperty("errors").TryGetProperty(expectedErrorKey, out _));
        foreach (var forbidden in new[] { "Exception", "StackTrace", "   at ", "SELECT", "Npgsql", "Host=", "Password" })
            Assert.DoesNotContain(forbidden, text, StringComparison.Ordinal);
    }

    // T-01
    [Fact]
    public async Task T01_ValidPost_Returns201_WithServerManagedFields()
    {
        var title = NewTitle("T01");
        try
        {
            using var response = await _client.PostAsJsonAsync("/api/incidents",
                Body("  " + title + "  ", severity: "low"));
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            Assert.NotNull(response.Headers.Location);
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal(title, doc.RootElement.GetProperty("title").GetString()); // Trim
            Assert.Equal("Low", doc.RootElement.GetProperty("severity").GetString());
            Assert.Equal("New", doc.RootElement.GetProperty("status").GetString());
            Assert.False(doc.RootElement.TryGetProperty("ownerUserId", out _)); // чужих полів немає
        }
        finally { await CleanupAsync(title); }
    }

    // T-02
    [Theory]
    [InlineData("{\"title\":\" \",\"description\":\"valid\",\"severity\":\"Low\",\"occurredAtUtc\":\"2026-09-01T10:00:00Z\"}", "title")]
    [InlineData("{\"title\":\"T02\",\"description\":\" \",\"severity\":\"Low\",\"occurredAtUtc\":\"2026-09-01T10:00:00Z\"}", "description")]
    [InlineData("{\"title\":\"T02\",\"description\":\"valid\",\"severity\":\"7\",\"occurredAtUtc\":\"2026-09-01T10:00:00Z\"}", "severity")]
    [InlineData("{\"title\":\"T02\",\"description\":\"valid\",\"severity\":\"Nope\",\"occurredAtUtc\":\"2026-09-01T10:00:00Z\"}", "severity")]
    [InlineData("{\"title\":\"T02\",\"description\":\"valid\",\"severity\":\"Low\"}", "occurredAtUtc")]
    [InlineData("{\"title\":\"T02\",\"description\":\"valid\",\"severity\":\"Low\",\"occurredAtUtc\":\"2099-01-01T00:00:00Z\"}", "occurredAtUtc")]
    public async Task T02_InvalidDto_Returns400Problem(string json, string key)
    {
        using var response = await _client.PostAsync("/api/incidents", Json(json));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertSafeProblemAsync(response, key);
    }

    [Fact]
    public async Task T02_TooLongTitleAndDescription_Return400()
    {
        using var r1 = await _client.PostAsJsonAsync("/api/incidents", Body(new string('x', 161)));
        Assert.Equal(HttpStatusCode.BadRequest, r1.StatusCode);
        await AssertSafeProblemAsync(r1, "title");

        using var r2 = await _client.PostAsJsonAsync("/api/incidents",
            Body(NewTitle("T02len"), description: new string('d', 4001)));
        Assert.Equal(HttpStatusCode.BadRequest, r2.StatusCode);
        await AssertSafeProblemAsync(r2, "description");
    }

    // T-03: конфлікт
    [Fact]
    public async Task T03_DuplicateActiveTitle_Returns409_ButClosedDoesNotBlock()
    {
        var title = NewTitle("T03");
        try
        {
            using var first = await _client.PostAsJsonAsync("/api/incidents", Body(title));
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);

            using var second = await _client.PostAsJsonAsync("/api/incidents", Body("  " + title + " "));
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
            await AssertSafeProblemAsync(second, "");

            using var otherCase = await _client.PostAsJsonAsync("/api/incidents", Body(title.ToUpperInvariant()));
            Assert.Equal(HttpStatusCode.Created, otherCase.StatusCode);
            await CleanupAsync(title.ToUpperInvariant());

           
            await using (var scope = factory.Services.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
                await db.Incidents.Where(item => item.Title == title)
                    .ExecuteUpdateAsync(s => s.SetProperty(item => item.Status, IncidentStatus.Closed));
            }
            using var third = await _client.PostAsJsonAsync("/api/incidents", Body(title));
            Assert.Equal(HttpStatusCode.Created, third.StatusCode);
        }
        finally { await CleanupAsync(title); await CleanupAsync(title.ToUpperInvariant()); }
    }

    // T-09: межа 39/40
    [Theory]
    [InlineData("High")]
    [InlineData("Critical")]
    public async Task T09_HighOrCritical_Boundary39And40(string severity)
    {
        var title = NewTitle("T09");
        try
        {
            using var r39 = await _client.PostAsJsonAsync("/api/incidents",
                Body(title, severity, new string('x', 39)));
            Assert.Equal(HttpStatusCode.BadRequest, r39.StatusCode);
            await AssertSafeProblemAsync(r39, "description");

            using var r40 = await _client.PostAsJsonAsync("/api/incidents",
                Body(title, severity, "  " + new string('x', 40) + "  "));
            Assert.Equal(HttpStatusCode.Created, r40.StatusCode);
        }
        finally { await CleanupAsync(title); }
    }

    [Fact]
    public async Task T09_LowSeverity_ShortDescription_IsAllowed()
    {
        var title = NewTitle("T09low");
        try
        {
            using var response = await _client.PostAsJsonAsync("/api/incidents", Body(title, "Low", "коротко"));
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        }
        finally { await CleanupAsync(title); }
    }

    // T-10: 
    [Fact]
    public async Task T10_OccurredAtOlderThan365Days_Returns400_Recent_Returns201()
    {
        var title = NewTitle("T10");
        try
        {
            using var old = await _client.PostAsJsonAsync("/api/incidents",
                Body(title, occurred: DateTimeOffset.UtcNow.AddDays(-400)));
            Assert.Equal(HttpStatusCode.BadRequest, old.StatusCode);
            await AssertSafeProblemAsync(old, "occurredAtUtc");

            using var ok = await _client.PostAsJsonAsync("/api/incidents",
                Body(title, occurred: DateTimeOffset.UtcNow.AddDays(-30)));
            Assert.Equal(HttpStatusCode.Created, ok.StatusCode);
        }
        finally { await CleanupAsync(title); }
    }

    // A-02: overposting
    [Fact]
    public async Task A02_Overposting_ExtraFieldsAreIgnored()
    {
        var title = NewTitle("A02");
        var fakeId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var fakeOwner = Guid.Parse("22222222-2222-2222-2222-222222222222");
        try
        {
            var body = new
            {
                title,
                description = "Перевірка overposting.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
                id = fakeId, ownerUserId = fakeOwner, status = "Closed",
                createdAtUtc = "2000-01-01T00:00:00Z"
            };
            using var response = await _client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);

            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            var saved = await db.Incidents.AsNoTracking().SingleAsync(item => item.Title == title);
            Assert.NotEqual(fakeId, saved.Id);
            Assert.Equal(IncidentStatus.New, saved.Status);
            Assert.Equal(DbSeeder.AliceId, saved.OwnerUserId);
            Assert.True(saved.CreatedAtUtc > new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero));
        }
        finally { await CleanupAsync(title); }
    }
}