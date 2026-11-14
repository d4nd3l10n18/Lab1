using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    private static readonly HashSet<string> AllowedStatusNames =
        new(Enum.GetNames<IncidentStatus>(), StringComparer.OrdinalIgnoreCase);

    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents")
            .RequireAuthorization();

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPut("/{id:guid}", UpdateAsync)
            .WithName("UpdateIncident")
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapDelete("/{id:guid}", DeleteAsync)
            .WithName("DeleteIncident")
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident")
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>()
            .ProducesValidationProblem();

        endpoints.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .WithName("GetIncidentComment")
            .WithTags("Incidents")
            .RequireAuthorization()
            .Produces<IncidentCommentResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        return endpoints;
    }


    private static bool TryParseStatus(string? status, out IncidentStatus? parsedStatus)
    {
        parsedStatus = null;
        if (status is null)
        {
            return true;
        }

        if (!AllowedStatusNames.Contains(status))
        {
            return false;
        }

        parsedStatus = Enum.Parse<IncidentStatus>(status, ignoreCase: true);
        return true;
    }

    private static IResult StatusValidationProblem() =>
        Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
        });

    private static IResult IncidentNotFound() => Results.Problem(
        title: "Інцидент не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    private static IResult CommentNotFound() => Results.Problem(
        title: "Коментар не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    private static bool TryGetUserId(HttpContext httpContext, out Guid userId) =>
        Guid.TryParse(httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier), out userId);

    private static async Task<bool> IsAllowedAsync(
        IAuthorizationService authorizationService,
        HttpContext httpContext,
        object resource,
        OperationAuthorizationRequirement operation) =>
        (await authorizationService.AuthorizeAsync(httpContext.User, resource, operation)).Succeeded;

    private static Dictionary<string, string[]> ValidateContent(UpdateIncidentRequest request)
    {
        var errors = new Dictionary<string, string[]>();

        if (string.IsNullOrWhiteSpace(request.Title))
            errors["title"] = ["Title обов'язковий."];
        else if (request.Title.Trim().Length > 160)
            errors["title"] = ["Title не довший за 160 символів."];

        if (string.IsNullOrWhiteSpace(request.Description))
            errors["description"] = ["Description обов'язковий."];
        else if (request.Description.Trim().Length > 4000)
            errors["description"] = ["Description не довший за 4000 символів."];

        return errors;
    }

    private static void LogDenied(
        ILoggerFactory loggerFactory, HttpContext httpContext, string action, Guid resourceId) =>
        loggerFactory.CreateLogger("SecureLab.Audit").LogWarning(
            "authorization.denied subject={SubjectId} action={Action} resource={ResourceId} "
            + "result={Result} occurredAtUtc={OccurredAtUtc:O} traceId={TraceId}",
            httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier),
            action,
            resourceId,
            "denied",
            DateTimeOffset.UtcNow,
            Activity.Current?.Id ?? httpContext.TraceIdentifier);


    private static async Task<IResult> GetListAsync(
        string? status,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (!TryParseStatus(status, out var parsedStatus))
        {
            return StatusValidationProblem();
        }

        if (!TryGetUserId(httpContext, out var userId))
        {
            return Results.Challenge();
        }

        var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);
        return Results.Ok(await queries.GetListAsync(parsedStatus, userId, isAnalyst, cancellationToken));
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        string? status,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (!TryParseStatus(status, out var parsedStatus))
        {
            return StatusValidationProblem();
        }

        if (!TryGetUserId(httpContext, out var userId))
        {
            return Results.Challenge();
        }

        var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);
        return Results.Ok(
            await queries.GetSeveritySummaryAsync(parsedStatus, userId, isAnalyst, cancellationToken));
    }


    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await queries.FindAsync(id, track: false, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        if (!await IsAllowedAsync(authorizationService, httpContext, incident, IncidentOperations.Read))
        {
            return IncidentNotFound();
        }

        var includeInternal = await IsAllowedAsync(
            authorizationService, httpContext, incident, IncidentOperations.ReadInternalComments);

        var details = await queries.GetDetailsAsync(id, includeInternal, cancellationToken);
        return details is null ? IncidentNotFound() : Results.Ok(details);
    }

    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        IncidentQueries queries,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await queries.FindAsync(id, track: true, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        if (!await IsAllowedAsync(authorizationService, httpContext, incident, IncidentOperations.Read))
        {
            return IncidentNotFound();
        }

        if (!await IsAllowedAsync(authorizationService, httpContext, incident, IncidentOperations.Update))
        {
            return Results.Forbid();
        }

        var errors = ValidateContent(request);
        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors);
        }

        incident.Title = request.Title!.Trim();
        incident.Description = request.Description!.Trim();
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }


    private static async Task<IResult> DeleteAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        IncidentQueries queries,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await queries.FindAsync(id, track: true, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        if (!await IsAllowedAsync(authorizationService, httpContext, incident, IncidentOperations.Read))
        {
            return IncidentNotFound();
        }

        if (!await IsAllowedAsync(authorizationService, httpContext, incident, IncidentOperations.Delete))
        {
            return Results.Forbid();
        }

        dbContext.Incidents.Remove(incident);
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }


    private static async Task<IResult> TriageAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        IncidentQueries queries,
        SecureLabDbContext dbContext,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken)
    {
        var incident = await queries.FindAsync(id, track: true, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        if (!await IsAllowedAsync(authorizationService, httpContext, incident, IncidentOperations.Read))
        {
            LogDenied(loggerFactory, httpContext, "incident.triage", incident.Id);
            return IncidentNotFound();
        }

        if (!await IsAllowedAsync(authorizationService, httpContext, incident, IncidentOperations.Triage))
        {
            LogDenied(loggerFactory, httpContext, "incident.triage", incident.Id);
            return Results.Forbid();
        }

        if (incident.Status != IncidentStatus.New)
        {
            return Results.Problem(
                title: "Перехід неможливий",
                detail: "Triage дозволений лише для інциденту зі статусом New.",
                statusCode: StatusCodes.Status409Conflict);
        }

        if (!TryGetUserId(httpContext, out var userId))
        {
            return Results.Challenge();
        }

        var now = DateTimeOffset.UtcNow;
        var oldStatus = incident.Status;
        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = now;
        dbContext.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(),
            IncidentId = incident.Id,
            ChangedByUserId = userId,
            OldStatus = oldStatus,
            NewStatus = IncidentStatus.Triaged,
            Note = "Triage через API.",
            CreatedAtUtc = now
        });
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }


    private static async Task<IResult> GetCommentAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var comment = await queries.FindCommentAsync(id, cancellationToken);
        if (comment is null)
        {
            return CommentNotFound();
        }

        // Те саме централізоване рішення, але для parent incident.
        if (!await IsAllowedAsync(authorizationService, httpContext, comment.Incident, IncidentOperations.Read))
        {
            return CommentNotFound();
        }

        if (comment.IsInternal
            && !await IsAllowedAsync(
                authorizationService, httpContext, comment.Incident, IncidentOperations.ReadInternalComments))
        {
            return CommentNotFound();
        }

        return Results.Ok(new IncidentCommentResponse(
            comment.Id,
            comment.Author.DisplayName,
            comment.Text,
            comment.CreatedAtUtc));
    }
}