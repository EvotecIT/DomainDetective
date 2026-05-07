using System;
using System.Collections.Generic;

namespace DomainDetective;

internal static class AgentReadinessLinkHeaderParser {
    public static IReadOnlyList<AgentReadinessLinkRelation> Parse(string? headerValue, Uri sourceUri) {
        var links = new List<AgentReadinessLinkRelation>();
        if (string.IsNullOrWhiteSpace(headerValue)) {
            return links;
        }

        var header = headerValue!;
        foreach (var segment in SplitHeader(header)) {
            var trimmed = segment.Trim();
            if (trimmed.Length == 0 || trimmed[0] != '<') {
                continue;
            }

            var close = trimmed.IndexOf('>');
            if (close <= 1) {
                continue;
            }

            var targetText = trimmed.Substring(1, close - 1);
            if (!Uri.TryCreate(sourceUri, targetText, out var target)) {
                continue;
            }

            var parameters = ParseParameters(trimmed.Substring(close + 1));
            if (!parameters.TryGetValue("rel", out var relValue) || string.IsNullOrWhiteSpace(relValue)) {
                continue;
            }

            foreach (var rel in relValue.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)) {
                var relation = new AgentReadinessLinkRelation {
                    Relation = rel,
                    Target = target.AbsoluteUri,
                    SourceUrl = sourceUri.AbsoluteUri,
                    Type = parameters.TryGetValue("type", out var type) ? type : null,
                    Raw = trimmed
                };
                foreach (var kvp in parameters) {
                    relation.Parameters[kvp.Key] = kvp.Value;
                }
                links.Add(relation);
            }
        }

        return links;
    }

    private static IEnumerable<string> SplitHeader(string value) {
        var start = 0;
        var inQuotes = false;
        var inAngle = false;
        for (var i = 0; i < value.Length; i++) {
            var c = value[i];
            if (c == '"' && (i == 0 || value[i - 1] != '\\')) {
                inQuotes = !inQuotes;
            } else if (!inQuotes && c == '<') {
                inAngle = true;
            } else if (!inQuotes && c == '>') {
                inAngle = false;
            } else if (!inQuotes && !inAngle && c == ',') {
                yield return value.Substring(start, i - start);
                start = i + 1;
            }
        }

        yield return value.Substring(start);
    }

    private static Dictionary<string, string> ParseParameters(string value) {
        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawPart in SplitParameters(value)) {
            var part = rawPart.Trim();
            if (part.Length == 0) {
                continue;
            }
            if (part[0] == ';') {
                part = part.Substring(1).Trim();
            }
            var equals = part.IndexOf('=');
            if (equals <= 0) {
                continue;
            }

            var name = part.Substring(0, equals).Trim();
            var val = part.Substring(equals + 1).Trim();
            if (val.Length >= 2 && val[0] == '"' && val[val.Length - 1] == '"') {
                val = val.Substring(1, val.Length - 2).Replace("\\\"", "\"");
            }
            if (name.Length > 0) {
                parameters[name] = val;
            }
        }

        return parameters;
    }

    private static IEnumerable<string> SplitParameters(string value) {
        var start = 0;
        var inQuotes = false;
        for (var i = 0; i < value.Length; i++) {
            if (value[i] == '"' && (i == 0 || value[i - 1] != '\\')) {
                inQuotes = !inQuotes;
            } else if (!inQuotes && value[i] == ';') {
                yield return value.Substring(start, i - start);
                start = i;
            }
        }

        yield return value.Substring(start);
    }
}
