using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class Lab03DeepeningTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{

    [Fact]
    public async Task SecurityStampUpdate_InvalidatesExistingSession_OnNextRequest()
    {
        var userName = TestAuth.NewUserName();
        using var host = factory.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
            s.Configure<SecurityStampValidatorOptions>(o => o.ValidationInterval = TimeSpan.Zero)));
        using var client = host.CreateClient(TestAuth.Https());
        try
        {
            using var reg = await client.PostAsJsonAsync("/api/auth/register", TestAuth.RegistrationBody(userName));
            Assert.Equal(HttpStatusCode.Created, reg.StatusCode);
            using var login = await client.PostAsJsonAsync("/api/auth/login",
                new { userName, password = TestAuth.Password });
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
            using (var before = await client.GetAsync("/api/me"))
                Assert.Equal(HttpStatusCode.OK, before.StatusCode);

            await using (var scope = host.Services.CreateAsyncScope())
            {
                var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                var user = await users.FindByNameAsync(userName);
                Assert.NotNull(user);
                Assert.True((await users.UpdateSecurityStampAsync(user!)).Succeeded);
            }

            using var after = await client.GetAsync("/api/me");     // той самий cookie, але stamp змінено
            Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
        }
        finally { await TestDb.DeleteUserAsync(host.Services, userName); }
    }


    [Fact]
    public async Task WeakerLegacyHash_IsRehashed_AfterSuccessfulLogin()
    {
        var userName = TestAuth.NewUserName();
        var password = TestAuth.Password;
        var current = new PasswordHasher<ApplicationUser>();
        var legacy = new PasswordHasher<ApplicationUser>(
            Options.Create(new PasswordHasherOptions { IterationCount = 10_000 }));
        using var client = factory.CreateClient(TestAuth.Https());
        try
        {
            using var reg = await client.PostAsJsonAsync("/api/auth/register", TestAuth.RegistrationBody(userName));
            Assert.Equal(HttpStatusCode.Created, reg.StatusCode);

            string weakHash;
            await using (var scope = factory.Services.CreateAsyncScope())
            {
                var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                var user = (await users.FindByNameAsync(userName))!;
                weakHash = legacy.HashPassword(user, password);
                user.PasswordHash = weakHash;
                Assert.True((await users.UpdateAsync(user)).Succeeded);


                Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded,
                    current.VerifyHashedPassword(user, weakHash, password));
            }

            using var login = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);

            await using (var scope = factory.Services.CreateAsyncScope())
            {
                var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                var user = (await users.FindByNameAsync(userName))!;

                Assert.True(user.PasswordHash != weakHash);
                Assert.Equal(PasswordVerificationResult.Success,
                    current.VerifyHashedPassword(user, user.PasswordHash!, password));
            }
        }
        finally { await TestDb.DeleteUserAsync(factory.Services, userName); }
    }
}