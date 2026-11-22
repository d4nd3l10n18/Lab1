using Microsoft.AspNetCore.Antiforgery;
namespace SecureLab.Api.Security;
public sealed class CsrfValidation : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try { await context.HttpContext.RequestServices.GetRequiredService<IAntiforgery>()
            .ValidateRequestAsync(context.HttpContext); }
        catch (AntiforgeryValidationException)
        {
            return Results.Problem(title: "Antiforgery validation failed", statusCode: 400);
        }
        return await next(context);
    }
}
