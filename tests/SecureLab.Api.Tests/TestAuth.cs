using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public static class TestAuth
{
    public static string Password =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    public static string WrongPassword() => "Wrong-" + Guid.NewGuid().ToString("N") + "!Aa1";
    public static string NewUserName() => "u" + Guid.NewGuid().ToString("N")[..12];

    public static WebApplicationFactoryClientOptions Https(bool cookies = true) => new()
    {
        BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = cookies
    };

    public static object RegistrationBody(string userName, string? email = null) => new
    {
        userName,
        email = email ?? userName + "@example.test",
        displayName = "Тест " + userName,
        password = Password
    };
}

public static class TestDb
{
    public static async Task DeleteUserAsync(IServiceProvider services, string userName)
    {
        await using var scope = services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByNameAsync(userName);
        if (user is not null) await users.DeleteAsync(user);
    }

    public static async Task DeleteIncidentsAsync(IServiceProvider services, string title)
    {
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(i => i.Title == title).ExecuteDeleteAsync();
    }
}