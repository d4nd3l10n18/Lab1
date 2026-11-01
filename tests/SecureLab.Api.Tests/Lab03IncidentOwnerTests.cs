using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class Lab03IncidentOwnerTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static readonly Dictionary<string, Guid> Ids = new()
    { ["alice"] = DbSeeder.AliceId, ["bob"] = DbSeeder.BobId };

    private static Dictionary<string, object?> Body(string title) => new()
    {
        ["title"] = title, ["description"] = "Перевірка власника нового запису.",
        ["severity"] = "Low", ["occurredAtUtc"] = DateTimeOffset.UtcNow.AddMinutes(-10)
    };

    private async Task<Guid> CreateAsync(HttpClient client, Dictionary<string, object?> body, string? demoHeader = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/incidents")
        { Content = JsonContent.Create(body) };
        if (demoHeader is not null) request.Headers.Add("X-Demo-UserId", demoHeader);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("id").GetGuid();
    }

    private async Task<Guid> OwnerOfAsync(Guid incidentId)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return (await db.Incidents.AsNoTracking().SingleAsync(i => i.Id == incidentId)).OwnerUserId;
    }

    // A-04
    [Theory]
    [InlineData("alice")]
    [InlineData("bob")]
    public async Task A04_CreateWithoutOwner_TakesOwnerFromPrincipal(string user)
    {
        var title = "A04-" + Guid.NewGuid().ToString("N");
        try
        {
            using var client = await factory.LoginAsync(user, TestAuth.Password);
            var id = await CreateAsync(client, Body(title));
            Assert.Equal(Ids[user], await OwnerOfAsync(id));
        }
        finally { await TestDb.DeleteIncidentsAsync(factory.Services, title); }
    }

    // A-05: Bob з owner Alice (і навпаки) + підроблений X-Demo-UserId
    [Theory]
    [InlineData("bob", "alice")]
    [InlineData("alice", "bob")]
    public async Task A05_ForgedOwnerInJson_DoesNotChangeOwner(string user, string victim)
    {
        var title = "A05-" + Guid.NewGuid().ToString("N");
        try
        {
            using var client = await factory.LoginAsync(user, TestAuth.Password);
            var body = Body(title);
            body["ownerUserId"] = Ids[victim];
            body["OwnerUserId"] = Ids[victim];
            body["createdByUserId"] = Ids[victim];

            var id = await CreateAsync(client, body, demoHeader: Ids[victim].ToString());

            var owner = await OwnerOfAsync(id);
            Assert.Equal(Ids[user], owner);
            Assert.NotEqual(Ids[victim], owner);
        }
        finally { await TestDb.DeleteIncidentsAsync(factory.Services, title); }
    }
}