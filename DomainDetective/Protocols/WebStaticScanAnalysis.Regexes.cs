using System.Text.RegularExpressions;

namespace DomainDetective;

/// <summary>
/// Regex helpers used by discovery and CSS processing, split for maintainability.
/// </summary>
public partial class WebStaticScanAnalysis
{
    private static readonly Regex _attrRegex = new(@"(?i)(?:src|href)\s*=\s*""([^""]+)""|(?:src|href)\s*=\s*'([^']+)'", RegexOptions.Compiled);
    private static readonly Regex _cssUrlRegex = new(@"(?i)url\((?:""([^""]+)""|'([^']+)'|([^)]+))\)", RegexOptions.Compiled);
    private static readonly Regex _cssImportRegex = new(@"(?i)@import\s+(?:url\(([^)]+)\)|""([^""]+)""|'([^']+)')", RegexOptions.Compiled);
    private static readonly string[] _resourceTags = new[] { "script", "img", "link", "iframe", "source" };
    private static readonly Regex _anchorHrefRegex = new("(?is)<a[^>]*?href=\\\"([^\\\"]+)\\\"|<a[^>]*?href='([^']+)'", RegexOptions.Compiled);
}
