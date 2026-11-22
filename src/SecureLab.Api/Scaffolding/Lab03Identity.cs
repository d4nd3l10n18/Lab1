using SecureLab.Api.Security;
using System.Net.Mail;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    private static readonly Regex UserNamePattern =
        new(@"^[A-Za-z0-9._@+-]{3,64}\z", RegexOptions.CultureInvariant);

    public static void MapLab03Identity(this WebApplication app)
    {

        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users) =>
        {
            var errors = ValidateRegistration(input);
            if (errors.Count > 0) return Results.ValidationProblem(errors);

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),                       
                UserName = input.UserName!.Trim(),
                Email = input.Email!.Trim(),
                DisplayName = input.DisplayName!.Trim()
            };
            var result = await users.CreateAsync(user, input.Password!); 
            if (!result.Succeeded) return MapRegistrationFailure(result);

            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");

            return Results.Created("/api/me", new RegisteredUserResponse(user.Id, user.UserName!, user.DisplayName));
        });


        app.MapPost("/api/auth/login", async (LoginInput input, SignInManager<ApplicationUser> signIn,
            UserManager<ApplicationUser> users, HttpContext http, ILoggerFactory loggers,
            AuditIntegrity audit) =>
        {
            var logger = loggers.CreateLogger("SecureLab.Auth");


            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password)
                || input.UserName.Length > 256 || input.Password.Length > 128)
            {
                LogAuthEvent(logger, "login", "failure", http);
                await audit.AppendAsync(AuditIntegrity.Describe(http, "auth.login", null, "denied"));
                return Results.Unauthorized();
            }

            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);
            if (!result.Succeeded)
            {
                LogAuthEvent(logger, "login", "failure", http);
                await audit.AppendAsync(AuditIntegrity.Describe(http, "auth.login", null, "denied"));
                return Results.Unauthorized();
            }

            var user = await users.FindByNameAsync(input.UserName);
            LogAuthEvent(logger, "login", "success", http, user?.Id);
            var auditEvent = AuditIntegrity.Describe(http, "auth.login", null, "success");
            auditEvent.ActorUserId = user?.Id;
            await audit.AppendAsync(auditEvent);
            return Results.NoContent();
        }).RequireRateLimiting(LoginRateLimiting.PolicyName);

        app.MapPost("/api/auth/logout", async (SignInManager<ApplicationUser> signIn, HttpContext http,
            ILoggerFactory loggers, AuditIntegrity audit) =>
        {
            var id = Guid.TryParse(http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var g) ? g : (Guid?)null;
            var auditEvent = AuditIntegrity.Describe(http, "auth.logout", null, "success");
            auditEvent.ActorUserId = id;
            await audit.AppendAsync(auditEvent);
            await signIn.SignOutAsync();
            LogAuthEvent(loggers.CreateLogger("SecureLab.Auth"), "logout", "success", http, id);
            return Results.NoContent();           
        }).RequireAuthorization().AddEndpointFilter<CsrfValidation>();

        app.MapGet("/api/me", GetCurrentUser).RequireAuthorization();

        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }

    private static IResult GetCurrentUser(HttpContext httpContext)
    {
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userId, out var verifiedUserId))
            return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);

        var userName = httpContext.User.FindFirst(ClaimTypes.Name)?.Value ?? string.Empty;
        var roles = httpContext.User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();
        return Results.Ok(new MeResponse(verifiedUserId, userName, roles));
    }

    private static Dictionary<string, string[]> ValidateRegistration(RegistrationInput input)
    {
        var errors = new Dictionary<string, string[]>();
        var userName = input.UserName?.Trim();
        var email = input.Email?.Trim();
        var displayName = input.DisplayName?.Trim();

        if (string.IsNullOrEmpty(userName))
            errors["userName"] = ["userName обов'язковий."];
        else if (!UserNamePattern.IsMatch(userName))
            errors["userName"] = ["3–64 символи: латинські літери, цифри та - . _ @ +"];

        if (string.IsNullOrEmpty(email))
            errors["email"] = ["email обов'язковий."];
        else if (email.Length > 256 || !MailAddress.TryCreate(email, out var parsed) || parsed.Address != email)
            errors["email"] = ["Некоректний email."];

        if (string.IsNullOrEmpty(displayName))
            errors["displayName"] = ["displayName обов'язковий."];
        else if (displayName.Length > 120 || displayName.Any(char.IsControl))
            errors["displayName"] = ["До 120 символів, без керівних символів."];

        if (string.IsNullOrEmpty(input.Password))
            errors["password"] = ["password обов'язковий."];
        else if (input.Password.Length > 128)
            errors["password"] = ["Пароль не довший за 128 символів."];

        return errors;
    }

    private static IResult MapRegistrationFailure(IdentityResult result)
    {
        var codes = result.Errors.Select(e => e.Code).ToHashSet(StringComparer.Ordinal);

        if (codes.Contains("DuplicateUserName") || codes.Contains("DuplicateEmail"))
            return Results.Problem(statusCode: StatusCodes.Status409Conflict,
                title: "Реєстрацію не виконано",
                detail: "Обліковий запис із такими даними вже існує.");

        var errors = new Dictionary<string, string[]>();
        if (codes.Any(c => c.StartsWith("Password", StringComparison.Ordinal)))
            errors["password"] = ["Мінімум 10 символів, велика й мала латинські літери, цифра та спецсимвол."];
        if (codes.Contains("InvalidUserName")) errors["userName"] = ["Недопустимі символи в userName."];
        if (codes.Contains("InvalidEmail")) errors["email"] = ["Некоректний email."];
        if (errors.Count == 0) errors["registration"] = ["Реєстрацію не виконано."];
        return Results.ValidationProblem(errors);
    }

    private static void LogAuthEvent(ILogger logger, string eventType, string result,
        HttpContext http, Guid? userId = null) =>
        logger.LogInformation(
            "Auth event {EventType}: result {Result}, user {UserId}, at {OccurredAtUtc}, trace {TraceId}",
            eventType, result, userId?.ToString() ?? "-", DateTimeOffset.UtcNow, http.TraceIdentifier);
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record LoginInput(string? UserName, string? Password);
public sealed record RegisteredUserResponse(Guid Id, string UserName, string DisplayName);
public sealed record MeResponse(Guid Id, string UserName, string[] Roles);