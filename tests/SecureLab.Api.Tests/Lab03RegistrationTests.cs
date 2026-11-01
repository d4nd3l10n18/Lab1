using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class Lab03RegistrationTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const string Url = "/api/auth/register";
    private HttpClient Client() => factory.CreateClient(TestAuth.Https(cookies: false));

    // T-01
    [Fact]
    public async Task T01_ValidRegistration_Returns201_WithSafeBody()
    {
        var userName = TestAuth.NewUserName();
        try
        {
            using var response = await Client().PostAsJsonAsync(Url, TestAuth.RegistrationBody(userName));
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            Assert.Equal("/api/me", response.Headers.Location?.OriginalString);
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal(new[] { "displayName", "id", "userName" },
                doc.RootElement.EnumerateObject().Select(p => p.Name).Order().ToArray());
            Assert.Equal(userName, doc.RootElement.GetProperty("userName").GetString());
        }
        finally { await TestDb.DeleteUserAsync(factory.Services, userName); }
    }

    // T-02: некоректні дані
    [Theory]
    [InlineData("password-too-short")]
    [InlineData("password-no-digit")]
    [InlineData("password-no-upper")]
    [InlineData("bad-email")]
    [InlineData("bad-username-chars")]
    [InlineData("blank-displayname")]
    [InlineData("displayname-121")]
    public async Task T02_Invalid_Returns400Problem_AndCreatesNoUser(string kind)
    {
        var userName = TestAuth.NewUserName();
        var email = userName + "@example.test";
        var displayName = "Тест";
        var password = TestAuth.Password;
        switch (kind)   // навмисно невалідні тестові значення, не реальні паролі
        {
            case "password-too-short": password = "Aa1!aaa"; break;
            case "password-no-digit": password = "Abcdefghij!"; break;
            case "password-no-upper": password = "abcdefghi1!"; break;
            case "bad-email": email = "not-an-email"; break;
            case "bad-username-chars": userName = "bad name<x>"; break;
            case "blank-displayname": displayName = "  "; break;
            case "displayname-121": displayName = new string('d', 121); break;
        }

        using var response = await Client().PostAsJsonAsync(Url, new { userName, email, displayName, password });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(JsonDocument.Parse(text).RootElement.TryGetProperty("errors", out _));
        Assert.False(text.Contains(password, StringComparison.Ordinal)); // пароль не відлунюється

        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        Assert.Null(await users.FindByNameAsync(userName));
    }

    // T-02 / duplicate-контракт: 409 і однаково безпечна відповідь для userName та email
    [Fact]
    public async Task T02_Duplicate_Returns409_WithoutRevealingWhichFieldClashed()
    {
        var first = TestAuth.NewUserName();
        var second = TestAuth.NewUserName();
        try
        {
            using var created = await Client().PostAsJsonAsync(Url, TestAuth.RegistrationBody(first));
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);

            using var sameName = await Client().PostAsJsonAsync(Url,
                TestAuth.RegistrationBody(first, email: second + "@example.test"));
            using var sameEmail = await Client().PostAsJsonAsync(Url,
                TestAuth.RegistrationBody(second, email: first + "@example.test"));

            Assert.Equal(HttpStatusCode.Conflict, sameName.StatusCode);
            Assert.Equal(HttpStatusCode.Conflict, sameEmail.StatusCode);
            Assert.Equal("application/problem+json", sameName.Content.Headers.ContentType?.MediaType);
            Assert.Equal(await ProblemShape.ReadAsync(sameName), await ProblemShape.ReadAsync(sameEmail));
        }
        finally
        {
            await TestDb.DeleteUserAsync(factory.Services, first);
            await TestDb.DeleteUserAsync(factory.Services, second);
        }
    }

    // зайві role/id ігноруються
    [Fact]
    public async Task Register_ExtraRoleAndId_AreIgnored()
    {
        var userName = TestAuth.NewUserName();
        var fakeId = Guid.NewGuid();
        try
        {
            using var response = await Client().PostAsJsonAsync(Url, new
            {
                userName, email = userName + "@example.test", displayName = "Тест",
                password = TestAuth.Password, role = "Administrator", id = fakeId, passwordHash = "x"
            });
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.NotEqual(fakeId, doc.RootElement.GetProperty("id").GetGuid());

            await using var scope = factory.Services.CreateAsyncScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = (await users.FindByNameAsync(userName))!;
            Assert.Equal(new[] { DbSeeder.ReporterRole }, (await users.GetRolesAsync(user)).ToArray());
        }
        finally { await TestDb.DeleteUserAsync(factory.Services, userName); }
    }

    // T-03: у БД не пароль; два акаунти з однаковим паролем мають різні hash (сіль)
    [Fact]
    public async Task T03_StoredPassword_IsSaltedHash_NotPlaintext()
    {
        var a = TestAuth.NewUserName();
        var b = TestAuth.NewUserName();
        var password = TestAuth.Password;
        try
        {
            using var r1 = await Client().PostAsJsonAsync(Url, TestAuth.RegistrationBody(a));
            using var r2 = await Client().PostAsJsonAsync(Url, TestAuth.RegistrationBody(b));
            Assert.Equal(HttpStatusCode.Created, r1.StatusCode);
            Assert.Equal(HttpStatusCode.Created, r2.StatusCode);

            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            var h1 = (await db.Users.AsNoTracking().SingleAsync(u => u.UserName == a)).PasswordHash;
            var h2 = (await db.Users.AsNoTracking().SingleAsync(u => u.UserName == b)).PasswordHash;

            // Assert.True, а не Assert.Equal: xUnit у failure друкує значення, а hash виводити не можна.
            Assert.False(string.IsNullOrEmpty(h1));
            Assert.True(h1 != password);
            Assert.False(h1!.Contains(password, StringComparison.Ordinal));
            Assert.True(h1 != h2);
        }
        finally
        {
            await TestDb.DeleteUserAsync(factory.Services, a);
            await TestDb.DeleteUserAsync(factory.Services, b);
        }
    }
}