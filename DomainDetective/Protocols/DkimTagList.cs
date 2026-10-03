using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace DomainDetective;

/// <summary>DKIM tag-list syntax, shared by key policy and signature diagnostics.</summary>
internal static class DkimTagList {
    internal static bool TryParse(string value, out Dictionary<string, string> tags, out bool duplicateTags) {
        tags = new Dictionary<string, string>(StringComparer.Ordinal);
        duplicateTags = false;
        string[] terms = value.Split(';');
        for (int i = 0; i < terms.Length; i++) {
            string term = terms[i].Trim(' ', '\t', '\r', '\n');
            if (term.Length == 0) {
                if (i == terms.Length - 1) continue;
                return false;
            }
            int equals = term.IndexOf('=');
            if (equals <= 0) return false;
            string name = term.Substring(0, equals).Trim(' ', '\t', '\r', '\n');
            if (!Regex.IsMatch(name, @"^[A-Za-z][A-Za-z0-9_]*$")) return false;
            if (tags.ContainsKey(name)) { duplicateTags = true; return false; }
            string text = term.Substring(equals + 1).Trim(' ', '\t', '\r', '\n');
            if (text.Any(ch => char.IsControl(ch) && ch != '\t' && ch != '\r' && ch != '\n')) return false;
            if (Regex.IsMatch(text, @"\r(?!\n[ \t])|(?<!\r)\n|\r\n(?![ \t])")) return false;
            tags.Add(name, text);
        }
        return tags.Count > 0;
    }

    internal static string RemoveFws(string value) => new(value.Where(ch => ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n').ToArray());
}
