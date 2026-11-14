using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using System.Security.Claims;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
    app.MapGet("/api/incidents/search", async (string? q, string? sortBy, HttpContext httpContext, SecureLabDbContext db, CancellationToken ct) =>
            {
                if (!Guid.TryParse(httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var userId))
                    return Results.Challenge();
                var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);

                var pattern = "%" + EscapeLike(q ?? "") + "%";
                var found = db.Incidents.AsNoTracking()
                    .Where(item => isAnalyst || item.OwnerUserId == userId)
                    .Where(item => EF.Functions.ILike(item.Title, pattern, "\\")
                                || EF.Functions.ILike(item.Description, pattern, "\\"));

                
                IOrderedQueryable<Incident>? ordered = sortBy switch
                {
                    null or "" or "createdAtUtc" => found
                        .OrderByDescending(item => item.CreatedAtUtc).ThenBy(item => item.Id),
                    "severity" => found
                        .OrderBy(item => item.Severity == IncidentSeverity.Critical ? 0
                                    : item.Severity == IncidentSeverity.High ? 1
                                    : item.Severity == IncidentSeverity.Medium ? 2 : 3)
                        .ThenBy(item => item.Id),
                    "status" => found
                        .OrderBy(item => item.Status == IncidentStatus.New ? 0
                                    : item.Status == IncidentStatus.Triaged ? 1
                                    : item.Status == IncidentStatus.InProgress ? 2
                                    : item.Status == IncidentStatus.Resolved ? 3 : 4)
                        .ThenBy(item => item.Id),
                    _ => null
                };

                if (ordered is null)
                    return Results.ValidationProblem(new Dictionary<string, string[]>
                    {
                        ["sortBy"] = ["Допустимі значення: createdAtUtc, severity, status."]
                    });

                var items = await ordered
                    .Take(50)
                    .Select(item => new IncidentSearchItem(
                        item.Id, item.Title, item.Description,
                        item.Severity.ToString(), item.Status.ToString(), item.CreatedAtUtc))
                    .ToListAsync(ct);
                return Results.Ok(items);
            }).RequireAuthorization();
        app.MapPost("/api/incidents", async (CreateIncidentRequest request, HttpContext httpContext, SecureLabDbContext db, CancellationToken ct) =>
        {

            if (!Guid.TryParse(httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var ownerId))
                return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
           
            var now = DateTimeOffset.UtcNow;
            var errors = new Dictionary<string, string[]>();

            
            if (string.IsNullOrWhiteSpace(request.Title))
                errors["title"] = ["Title обов'язковий."];
            else if (request.Title.Length > 160)
                errors["title"] = ["Title не довший за 160 символів."];

            if (string.IsNullOrWhiteSpace(request.Description))
                errors["description"] = ["Description обов'язковий."];
            else if (request.Description.Length > 4000)
                errors["description"] = ["Description не довший за 4000 символів."];

           
            var severityIsValid =
                Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity)
                && Enum.IsDefined(severity);
            if (!severityIsValid)
                errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];

           
            if (request.OccurredAtUtc is null)
                errors["occurredAtUtc"] = ["occurredAtUtc обов'язковий."];
            else if (request.OccurredAtUtc.Value > now.AddMinutes(5))
                errors["occurredAtUtc"] = ["occurredAtUtc не може бути більш ніж на 5 хвилин у майбутньому."];
            else if (request.OccurredAtUtc.Value < now.AddDays(-365))
                errors["occurredAtUtc"] = ["occurredAtUtc не може бути раніше ніж 365 днів тому."];

           
            var title = request.Title?.Trim() ?? "";
            var description = request.Description?.Trim() ?? "";

            
            if (severityIsValid
                && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical)
                && !errors.ContainsKey("description")
                && description.Length < 40)
                errors["description"] = ["Для High/Critical description має містити щонайменше 40 символів."];

            
            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            
            var duplicate = await db.Incidents.AnyAsync(
                item => item.Title == title && item.Status != IncidentStatus.Closed, ct);
            if (duplicate)
                return Results.Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Інцидент уже існує",
                    detail: "Незакритий інцидент із таким заголовком уже зареєстровано.");

           
            var incident = new Incident
            {
                Id = Guid.NewGuid(),
                OwnerUserId = ownerId,
                Title = title,
                Description = description,
                Severity = severity,
                Status = IncidentStatus.New,
                OccurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime(),
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            };
            db.Incidents.Add(incident);
            await db.SaveChangesAsync(ct);

            var response = new CreatedIncidentResponse(
                incident.Id, incident.Title, incident.Severity.ToString(), incident.Status.ToString(),
                incident.OccurredAtUtc, incident.CreatedAtUtc, incident.UpdatedAtUtc);
                return Results.Created($"/api/incidents/{incident.Id}", response);
        }).RequireAuthorization();
    }
    
    private static string EscapeLike(string value) =>
        value.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
}

public sealed record CreateIncidentRequest(
    string? Title, string? Description, string? Severity, DateTimeOffset? OccurredAtUtc);

public sealed record CreatedIncidentResponse(
    Guid Id, string Title, string Severity, string Status,
    DateTimeOffset OccurredAtUtc, DateTimeOffset CreatedAtUtc, DateTimeOffset UpdatedAtUtc);

public sealed record IncidentSearchItem(
    Guid Id, string Title, string Description, string Severity, string Status, DateTimeOffset CreatedAtUtc);