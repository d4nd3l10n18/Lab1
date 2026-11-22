using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public static class CookieClient
{
    public static async Task<HttpClient> LoginAsync(this WebApplicationFactory<Program> factory, string userName, string password)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true
        });
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
        if (!response.IsSuccessStatusCode)
        {
            client.Dispose();
            throw new InvalidOperationException($"Study login failed: HTTP {(int)response.StatusCode} (credentials omitted).");
        }
        // Legacy positive tests send mutations through this client. A valid token in
        // DefaultRequestHeaders preserves those tests without relaxing server validation.
        var token = await client.GetCsrfTokenAsync();
        client.DefaultRequestHeaders.Add("X-SecureLab-CSRF", token);
        return client;
    }

    public static async Task<string> GetCsrfTokenAsync(this HttpClient client)
    {
        using var response = await client.GetAsync("/api/auth/csrf-token");
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("token").GetString()
            ?? throw new InvalidOperationException("Antiforgery token missing");
    }
}
