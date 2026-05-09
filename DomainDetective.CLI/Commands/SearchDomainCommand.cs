using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective.CLI;

/// <summary>
/// Settings for <see cref="SearchDomainCommand"/>.
/// </summary>
internal sealed class SearchDomainSettings : CommandSettings
{
    /// <summary>Keywords used to generate domains.</summary>
    [CommandArgument(0, "<keywords>")]
    public string[] Keywords { get; set; } = Array.Empty<string>();

    /// <summary>Optional prefix list.</summary>
    [CommandOption("--prefixes <PREFIXES>")]
    public string[] Prefixes { get; set; } = Array.Empty<string>();

    /// <summary>Optional suffix list.</summary>
    [CommandOption("--suffixes <SUFFIXES>")]
    public string[] Suffixes { get; set; } = Array.Empty<string>();

    /// <summary>TLDs to use.</summary>
    [CommandOption("--tlds <TLDS>")]
    public string[] Tlds { get; set; } = new[] { "com" };

    /// <summary>TLD preset name.</summary>
    [CommandOption("--preset <PRESET>")]
    public string? Preset { get; set; }

    /// <summary>Output format: text, json, json-stream, json-array.</summary>
    [CommandOption("--output <FMT>")]
    public string Output { get; set; } = "text";

    /// <summary>Minimum length for the domain label.</summary>
    [CommandOption("--min-length <N>")]
    public int MinLength { get; set; }

    /// <summary>Maximum length for the domain label.</summary>
    [CommandOption("--max-length <N>")]
    public int MaxLength { get; set; } = int.MaxValue;

    /// <summary>Number of concurrent RDAP requests.</summary>
    [CommandOption("--concurrency <N>")]
    public int Concurrency { get; set; } = 10;
}

/// <summary>
/// Searches domain availability using RDAP.
/// </summary>
internal sealed class SearchDomainCommand : AsyncCommand<SearchDomainSettings>
{
    /// <inheritdoc />
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize")]
    protected override async Task<int> ExecuteAsync(CommandContext context, SearchDomainSettings settings, CancellationToken cancellationToken)
    {
        if (settings.Keywords.Length == 0)
        {
            AnsiConsole.MarkupLine("[red]No keywords provided.[/]");
            return 1;
        }

        var search = new DomainAvailabilitySearch
        {
            Prefixes = settings.Prefixes,
            Suffixes = settings.Suffixes,
            Tlds = settings.Tlds,
            MinLength = settings.MinLength,
            MaxLength = settings.MaxLength,
            Concurrency = settings.Concurrency
        };

        if (!string.IsNullOrWhiteSpace(settings.Preset))
        {
            search.TldPreset = settings.Preset;
        }

        var results = search.SearchAsync(settings.Keywords, cancellationToken);

        switch (settings.Output.ToLowerInvariant())
        {
            case "json":
            {
                var list = new List<DomainAvailabilityResult>();
                await foreach (var r in results)
                {
                    list.Add(r);
                }
                var json = JsonSerializer.Serialize(list, DomainDetective.Helpers.JsonOptions.Default);
                Console.WriteLine(json);
                break;
            }
            case "json-stream":
            {
                await foreach (var r in results)
                {
                    Console.WriteLine(JsonSerializer.Serialize(r, DomainDetective.Helpers.JsonOptions.Default));
                }
                break;
            }
            case "json-array":
            {
                var list = new List<DomainAvailabilityResult>();
                await foreach (var r in results)
                {
                    list.Add(r);
                }
                Console.WriteLine(JsonSerializer.Serialize(list, DomainDetective.Helpers.JsonOptions.Default));
                break;
            }
            default:
            {
                await foreach (var r in results)
                {
                    var color = r.Available ? "green" : "red";
                    AnsiConsole.MarkupLine($"[{color}]{r.Domain} - {(r.Available ? "available" : "taken")}[/]");
                }
                break;
            }
        }

        return 0;
    }
}
