using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace DomainDetective;

/// <summary>Bounded tokenization of header clauses, respecting quoted strings and nested comments.</summary>
internal static class MessageHeaderValueParser {
    private static readonly Regex MethodPattern = new(@"^(?<method>[a-z0-9_-]+)(?:/\d+)?\s*=\s*(?<result>[a-z]+)\b", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
    private static readonly Regex PropertyPattern = new("(?<key>[a-z0-9_-]+(?:\\.[a-z0-9_-]+)?)\\s*=\\s*(?:\"(?<quoted>(?:\\\\.|[^\"\\\\])*)\"|(?<value>[^\\s;]+))", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));

    internal static List<string> Split(string value, char separator = ';', bool stripComments = false) {
        var parts = new List<string>();
        var part = new StringBuilder();
        var depth = 0;
        var quoted = false;
        var escaped = false;
        foreach (var ch in value) {
            if (escaped) {
                if (!stripComments || depth == 0) { part.Append(ch); }
                escaped = false;
                continue;
            }
            if (ch == '\\' && (quoted || depth > 0)) {
                if (!stripComments || depth == 0) { part.Append(ch); }
                escaped = true;
                continue;
            }
            if (ch == '"' && depth == 0) { quoted = !quoted; }
            if (!quoted && ch == '(') { depth++; }
            if (!quoted && ch == ')') {
                depth = Math.Max(0, depth - 1);
                if (stripComments) { if (depth == 0) { part.Append(' '); } continue; }
            }
            if (ch == separator && depth == 0 && !quoted) {
                parts.Add(part.ToString().Trim());
                part.Clear();
            } else if (!stripComments || depth == 0) {
                part.Append(ch);
            }
        }
        parts.Add(part.ToString().Trim());
        return parts;
    }

    internal static MessageAuthenticationEvidence ParseAuthentication(string name, string value, int index) {
        var result = new MessageAuthenticationEvidence { HeaderName = name, Raw = value, HeaderIndex = index };
        var clauses = Split(value, stripComments: true);
        var start = 0;
        if (clauses.Count > 0 && !MethodPattern.IsMatch(clauses[0]) && clauses[0].IndexOf('=') < 0) {
            result.AuthServId = clauses[0].Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries).Length > 0
                ? clauses[0].Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)[0] : null;
            start = 1;
        }
        for (var i = start; i < clauses.Count; i++) {
            var match = MethodPattern.Match(clauses[i]);
            if (!match.Success) { continue; }
            var method = new MessageAuthenticationMethod {
                Method = match.Groups["method"].Value.ToLowerInvariant(),
                Result = match.Groups["result"].Value.ToLowerInvariant(), Raw = clauses[i]
            };
            foreach (Match property in PropertyPattern.Matches(clauses[i].Substring(match.Length))) {
                AddProperty(method, property.Groups["key"].Value, property.Groups["quoted"].Success
                    ? property.Groups["quoted"].Value : property.Groups["value"].Value);
            }
            result.Methods.Add(method);
        }
        return result;
    }

    internal static Dictionary<string, string> ParseTags(string value) {
        return ParseTags(value, out _);
    }

    internal static Dictionary<string, string> ParseTags(string value, out bool duplicateTags) {
        duplicateTags = false;
        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var clause in Split(value)) {
            var equals = clause.IndexOf('=');
            if (equals > 0) {
                var key = clause.Substring(0, equals).Trim();
                if (tags.ContainsKey(key)) { duplicateTags = true; }
                else { tags[key] = clause.Substring(equals + 1).Trim(); }
            }
        }
        return tags;
    }

    internal static MessageAuthenticationEvidence ParseReceivedSpf(string value, int index) {
        var evidence = new MessageAuthenticationEvidence { HeaderName = "Received-SPF", Raw = value, HeaderIndex = index };
        var clauses = Split(value, stripComments: true);
        var first = clauses.Count == 0 ? string.Empty : clauses[0];
        var tokens = first.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0 || !Regex.IsMatch(tokens[0], @"^(pass|fail|softfail|neutral|none|temperror|permerror)$", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1))) { return evidence; }
        var method = new MessageAuthenticationMethod { Method = "spf", Result = tokens[0].ToLowerInvariant(), Raw = value };
        foreach (Match property in PropertyPattern.Matches(string.Join("; ", clauses))) {
            var key = property.Groups["key"].Value;
            var text = property.Groups["quoted"].Success ? property.Groups["quoted"].Value : property.Groups["value"].Value;
            AddProperty(method, key.Equals("envelope-from", StringComparison.OrdinalIgnoreCase) ? "smtp.mailfrom" : key.Equals("helo", StringComparison.OrdinalIgnoreCase) ? "smtp.helo" : key, text);
            if (key.Equals("receiver", StringComparison.OrdinalIgnoreCase)) {
                evidence.AmbiguousAuthServId = method.DuplicateProperties.Contains("receiver");
                evidence.AuthServId = evidence.AmbiguousAuthServId ? null : text;
            }
        }
        evidence.Methods.Add(method);
        return evidence;
    }

    private static void AddProperty(MessageAuthenticationMethod method, string key, string value) {
        if (method.Properties.ContainsKey(key)) { method.DuplicateProperties.Add(key.ToLowerInvariant()); }
        else { method.Properties[key] = value; }
    }
}
