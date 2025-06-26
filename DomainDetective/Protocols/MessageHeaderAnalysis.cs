using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Represents the results from parsing message headers.
/// </summary>
public class MessageHeaderAnalysis {
    /// <summary>The unparsed raw headers.</summary>
    public string? RawHeaders { get; internal set; }
    /// <summary>Parsed header values keyed by header name.</summary>
    public Dictionary<string, string> Headers { get; } = new(StringComparer.OrdinalIgnoreCase);
}
