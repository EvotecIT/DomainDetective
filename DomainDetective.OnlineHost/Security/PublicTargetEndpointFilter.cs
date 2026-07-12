using DomainDetective.Security;

/// <summary>Rejects direct OnlineHost targets that do not resolve exclusively to public addresses.</summary>
public sealed class PublicTargetEndpointFilter : IEndpointFilter {
    private readonly PublicNetworkTargetValidator _validator;

    /// <summary>Creates the endpoint filter.</summary>
    public PublicTargetEndpointFilter(PublicNetworkTargetValidator validator) {
        _validator = validator;
    }

    /// <inheritdoc />
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next) {
        var request = context.Arguments.OfType<AnalyzeDomainRequest>().FirstOrDefault();
        if (request == null) return await next(context).ConfigureAwait(false);

        var value = request.Domain?.Trim() ?? string.Empty;
        var host = Uri.TryCreate(value, UriKind.Absolute, out var uri) ? uri.Host : value.TrimEnd('.');
        var result = await _validator.ValidateAsync(host, context.HttpContext.RequestAborted).ConfigureAwait(false);
        if (!result.IsAllowed) {
            return TypedResults.ValidationProblem(new Dictionary<string, string[]> {
                ["domain"] = new[] { result.Error ?? "The target must resolve exclusively to public addresses." }
            });
        }

        return await next(context).ConfigureAwait(false);
    }
}
