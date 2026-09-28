using System.Text;

namespace DomainDetective.Reports.Markdown;

internal static class MarkdownReportText {
    internal static string Escape(string value) {
        var text = new StringBuilder();
        foreach (var ch in value) {
            if ("\\`*_{}[]()!|<>".IndexOf(ch) >= 0) { text.Append('\\'); }
            text.Append(ch);
        }
        return text.ToString();
    }
}
