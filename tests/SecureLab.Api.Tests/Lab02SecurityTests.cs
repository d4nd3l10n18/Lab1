using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class Lab02SecurityTests(SecureLabApiFactory factory) 
    : IClassFixture<SecureLabApiFactory>, IAsyncLifetime
{
    private HttpClient _client = null!;

    public async Task InitializeAsync() =>
        _client = await factory.LoginAsync("morgan", TestAuth.Password);

    public Task DisposeAsync()
    {
        _client.Dispose();
        return Task.CompletedTask;
    }

    private static readonly Guid UsbId = Guid.Parse("20000000-0000-0000-0000-000000000005");
    private static readonly Guid ObrienId = Guid.Parse("20000000-0000-0000-0000-000000000004");

    private async Task<List<IncidentSearchItem>> SearchAsync(string query)
    {
        var items = await _client.GetFromJsonAsync<List<IncidentSearchItem>>("/api/incidents/search" + query);
        Assert.NotNull(items);
        return items;
    }

    private static string Q(string value) => "?q=" + Uri.EscapeDataString(value);

 
    [Fact]
    public async Task S02_ControlInput_ReturnsEmptySet()
    {
        var items = await SearchAsync(Q("zz-no-match' OR TRUE -- "));
        Assert.Empty(items);
    }


    [Fact]
    public async Task S02_PositiveControl_UsbReturnsExactlyOneRecord()
    {
        var items = await SearchAsync(Q("USB"));
        var only = Assert.Single(items);
        Assert.Equal(UsbId, only.Id);
    }

    // T-04
    [Fact]
    public async Task T04_LegitimateApostrophe_FindsObrien()
    {
        var items = await SearchAsync(Q("O'Brien"));
        var only = Assert.Single(items);
        Assert.Equal(ObrienId, only.Id);
    }

    [Fact]
    public async Task T04_CyrillicApostrophe_FindsSeededIncident()
    {
        var items = await SearchAsync(Q("комп'ютерного"));
        Assert.Single(items);
    }

    [Theory]
    [InlineData("%")]
    [InlineData("_")]
    [InlineData("\\")]
    public async Task T04_Wildcards_AreLiteral_NoRecordsOnSeed(string value)
    {
        Assert.Empty(await SearchAsync(Q(value)));
    }

    // T-05
    [Theory]
    [InlineData("price")]
    [InlineData("title; select 1")]
    [InlineData("created_at_utc")]
    public async Task T05_UnknownSortBy_Returns400WithSortByKey(string sortBy)
    {
        using var response = await _client.GetAsync("/api/incidents/search?sortBy=" + Uri.EscapeDataString(sortBy));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var text = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(text);
        Assert.True(doc.RootElement.GetProperty("errors").TryGetProperty("sortBy", out _));
        Assert.DoesNotContain("SELECT", text, StringComparison.Ordinal);
    }

    
    [Theory]
    [InlineData("", "0004,0005,0003,0002,0001")]
    [InlineData("?sortBy=createdAtUtc", "0004,0005,0003,0002,0001")]
    [InlineData("?sortBy=severity", "0002,0001,0003,0004,0005")]
    [InlineData("?sortBy=status", "0003,0004,0005,0001,0002")]
    public async Task Sorting_UsesContractRanks(string query, string expectedSuffixes)
    {
        var items = await SearchAsync(query);
        var actual = string.Join(",", items.Select(item => item.Id.ToString()[^4..]));
        Assert.Equal(expectedSuffixes, actual);
    }
}