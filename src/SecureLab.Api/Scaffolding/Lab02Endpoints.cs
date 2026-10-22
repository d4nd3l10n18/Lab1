using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            
            var pattern = "%" + EscapeLike(q ?? "") + "%";
            var found = db.Incidents.AsNoTracking()
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
        });
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