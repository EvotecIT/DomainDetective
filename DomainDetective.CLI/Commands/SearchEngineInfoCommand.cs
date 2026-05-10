using Spectre.Console.Cli;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;

namespace DomainDetective.CLI
{

/// <summary>
/// Settings for <see cref="SearchEngineInfoCommand"/>.
/// </summary>
internal sealed class SearchEngineInfoSettings : CommandSettings
{
    /// <summary>Search query.</summary>
    [CommandArgument(0, "<query>")]
    public string Query { get; set; } = string.Empty;

    /// <summary>Search engine to use: google or bing.</summary>
    [CommandOption("--engine <ENGINE>")]
    public string Engine { get; set; } = "google";

    /// <summary>Google API key.</summary>
    [CommandOption("--google-key <KEY>")]
    public string? GoogleApiKey { get; set; }

    /// <summary>Google search engine identifier.</summary>
    [CommandOption("--google-cx <CX>")]
    public string? GoogleCx { get; set; }

    /// <summary>Google API endpoint.</summary>
    [CommandOption("--google-endpoint <URL>")]
    public string GoogleEndpoint { get; set; } = "https://www.googleapis.com/customsearch/v1";

    /// <summary>Bing API key.</summary>
    [CommandOption("--bing-key <KEY>")]
    public string? BingApiKey { get; set; }

    /// <summary>Bing API endpoint.</summary>
    [CommandOption("--bing-endpoint <URL>")]
    public string BingEndpoint { get; set; } = "https://api.bing.microsoft.com/v7.0/search";
}

/// <summary>
/// Queries search engines for information.
/// </summary>
internal sealed class SearchEngineInfoCommand : AsyncCommand<SearchEngineInfoSettings>
{
    /// <inheritdoc />
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    protected override async Task<int> ExecuteAsync(CommandContext context, SearchEngineInfoSettings settings, CancellationToken cancellationToken)
    {
        var analysis = new SearchEngineAnalysis
        {
            GoogleApiKey = settings.GoogleApiKey,
            GoogleCx = settings.GoogleCx,
            GoogleEndpoint = settings.GoogleEndpoint,
            BingApiKey = settings.BingApiKey,
            BingEndpoint = settings.BingEndpoint
        };

        object result = settings.Engine.ToLowerInvariant() switch
        {
            "bing" => await analysis.SearchBing(settings.Query, cancellationToken),
            "google" => await analysis.SearchGoogle(settings.Query, cancellationToken),
            _ => throw new InvalidOperationException("Engine must be 'google' or 'bing'.")
        };

        string json = System.Text.Json.JsonSerializer.Serialize(result, SearchEngineJson.Options);
        Console.WriteLine(json);
        return 0;
    }
}
}
