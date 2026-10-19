using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace DomainDetective;

/// <summary>Entries and source-completion evidence belonging to one certificate transparency query.</summary>
public sealed class CtLogQueryResult {
    internal static readonly CtLogQueryResult Empty = new(Array.Empty<JsonElement>(), false, Array.Empty<string>(), Array.Empty<string>());

    internal CtLogQueryResult(IEnumerable<JsonElement> entries, bool complete, IEnumerable<string> sources, IEnumerable<string> errors) {
        Entries = Array.AsReadOnly(entries.ToArray());
        Complete = complete;
        Sources = Array.AsReadOnly(sources.ToArray());
        TemplateFormatErrors = Array.AsReadOnly(errors.ToArray());
    }

    /// <summary>Entries retained from completed source responses, including partial-query results.</summary>
    public IReadOnlyList<JsonElement> Entries { get; }
    /// <summary>Whether every configured source returned valid evidence before the query ended.</summary>
    public bool Complete { get; }
    /// <summary>Discovery sources configured for this query.</summary>
    public IReadOnlyList<string> Sources { get; }
    /// <summary>Invalid source-template diagnostics for this query.</summary>
    public IReadOnlyList<string> TemplateFormatErrors { get; }
}
