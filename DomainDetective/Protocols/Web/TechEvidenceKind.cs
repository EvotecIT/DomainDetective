namespace DomainDetective;

/// <summary>
/// Classifies the source of a technology detection to make results explainable.
/// </summary>
public enum TechEvidenceKind
{
    /// <summary>Generic HTTP header such as Server or X-Powered-By.</summary>
    Header,
    /// <summary>Cookie name/value (from Set-Cookie response headers).</summary>
    Cookie,
    /// <summary>HTML meta tags (e.g., generator).</summary>
    Meta,
    /// <summary>Regular expression matched in the HTML body.</summary>
    Body,
    /// <summary>URL path matched (generic, non-typed).</summary>
    Path,
    /// <summary>JavaScript URL/source path matched.</summary>
    ScriptSrc,
    /// <summary>Stylesheet URL/source path matched.</summary>
    StylesheetSrc,
    /// <summary>Domain suffix (PSL/known provider suffix) matched.</summary>
    DomainSuffix,
    /// <summary>DNS evidence (e.g., TXT/CNAME verification records).</summary>
    Dns,
    /// <summary>Heuristic (best-effort) evidence outside strict rules.</summary>
    Heuristic
}

