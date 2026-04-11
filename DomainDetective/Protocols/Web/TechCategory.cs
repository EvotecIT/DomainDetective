namespace DomainDetective;

/// <summary>
/// Broad category for a detected technology to aid grouping and presentation.
/// </summary>
public enum TechCategory
{
    /// <summary>Represents the other value.</summary>
    Other = 0,
    /// <summary>Represents the verification value.</summary>
    Verification,
    /// <summary>Represents the web server value.</summary>
    WebServer,
    /// <summary>Represents the cms value.</summary>
    CMS,
    /// <summary>Represents the blog value.</summary>
    Blog,
    /// <summary>Represents the e commerce value.</summary>
    ECommerce,
    /// <summary>Represents the js framework value.</summary>
    JSFramework,
    /// <summary>Represents the js library value.</summary>
    JSLibrary,
    /// <summary>Represents the framework value.</summary>
    Framework,
    /// <summary>Represents the language value.</summary>
    Language,
    /// <summary>Represents the analytics value.</summary>
    Analytics,
    /// <summary>Represents the tag manager value.</summary>
    TagManager,
    /// <summary>Represents the security value.</summary>
    Security,
    /// <summary>Represents the cdn value.</summary>
    CDN,
    /// <summary>Represents the paa s value.</summary>
    PaaS,
    /// <summary>Represents the issue tracker value.</summary>
    IssueTracker,
    /// <summary>Represents the fonts value.</summary>
    Fonts,
}
