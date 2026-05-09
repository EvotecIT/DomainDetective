using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>Classifies the root document type of a sitemap XML document.</summary>
public enum SitemapDocumentKind {
    /// <summary>The sitemap document kind could not be determined.</summary>
    Unknown,
    /// <summary>The sitemap document is a urlset.</summary>
    UrlSet,
    /// <summary>The sitemap document is a sitemapindex.</summary>
    SitemapIndex
}

/// <summary>Represents one fetched sitemap XML document.</summary>
public sealed class SitemapDocument {
    /// <summary>URL of the sitemap document.</summary>
    public string Url { get; set; } = string.Empty;
    /// <summary>HTTP status code returned by the sitemap document request.</summary>
    public int? StatusCode { get; set; }
    /// <summary>Content type returned for the sitemap document.</summary>
    public string? ContentType { get; set; }
    /// <summary>True when the sitemap document returned a successful HTTP response.</summary>
    public bool Present { get; set; }
    /// <summary>True when the sitemap document is well-formed XML.</summary>
    public bool XmlValid { get; set; }
    /// <summary>True when the sitemap document validates against the official Sitemap protocol XML schema.</summary>
    public bool SchemaValid { get; set; }
    /// <summary>Number of Sitemap protocol XML schema validation errors.</summary>
    public int SchemaValidationErrorCount { get; set; }
    /// <summary>First Sitemap protocol XML schema validation error, when available.</summary>
    public string? SchemaValidationError { get; set; }
    /// <summary>True when the root element uses the standard sitemap namespace.</summary>
    public bool NamespaceValid { get; set; }
    /// <summary>Detected sitemap document kind.</summary>
    public SitemapDocumentKind Kind { get; set; }
    /// <summary>Error encountered while fetching or parsing the document.</summary>
    public string? Error { get; set; }
    /// <summary>Number of URL entries parsed from this document.</summary>
    public int UrlCount { get; set; }
    /// <summary>Number of nested sitemap entries parsed from this document.</summary>
    public int SitemapCount { get; set; }
    /// <summary>Number of XHTML alternate links parsed from this document.</summary>
    public int XhtmlAlternateLinkCount { get; set; }
    /// <summary>Number of Google image sitemap extension elements parsed from this document.</summary>
    public int ImageExtensionElementCount { get; set; }
    /// <summary>Number of Google news sitemap extension elements parsed from this document.</summary>
    public int NewsExtensionElementCount { get; set; }
    /// <summary>Number of Google video sitemap extension elements parsed from this document.</summary>
    public int VideoExtensionElementCount { get; set; }
}

/// <summary>Represents one URL entry from a sitemap urlset.</summary>
public sealed class SitemapUrlEntry {
    /// <summary>Source sitemap document URL.</summary>
    public string SitemapUrl { get; set; } = string.Empty;
    /// <summary>Value of the loc element.</summary>
    public string Location { get; set; } = string.Empty;
    /// <summary>Raw lastmod value when present.</summary>
    public string? LastModified { get; set; }
    /// <summary>True when the lastmod value is absent or parseable.</summary>
    public bool LastModifiedValid { get; set; } = true;
    /// <summary>Raw changefreq value when present.</summary>
    public string? ChangeFrequency { get; set; }
    /// <summary>True when the changefreq value is absent or valid.</summary>
    public bool ChangeFrequencyValid { get; set; } = true;
    /// <summary>Raw priority value when present.</summary>
    public string? Priority { get; set; }
    /// <summary>True when priority is absent or between 0.0 and 1.0.</summary>
    public bool PriorityValid { get; set; } = true;
    /// <summary>True when loc is an absolute HTTP or HTTPS URL.</summary>
    public bool LocationValid { get; set; } = true;
    /// <summary>True when the same loc appears more than once.</summary>
    public bool Duplicate { get; set; }
    /// <summary>Alternate language links declared under the URL entry.</summary>
    public List<SitemapAlternateLink> Alternates { get; } = new();
}

/// <summary>Represents an xhtml alternate link found in a sitemap URL entry.</summary>
public sealed class SitemapAlternateLink {
    /// <summary>rel attribute value.</summary>
    public string? Rel { get; set; }
    /// <summary>hreflang attribute value.</summary>
    public string? HrefLang { get; set; }
    /// <summary>href attribute value.</summary>
    public string? Href { get; set; }
}

/// <summary>Represents a reachability probe for one sitemap URL entry.</summary>
public sealed class SitemapUrlProbe {
    /// <summary>Original sitemap URL entry.</summary>
    public string Url { get; set; } = string.Empty;
    /// <summary>Final URL after redirects, when available.</summary>
    public string? FinalUrl { get; set; }
    /// <summary>Final HTTP status code when available.</summary>
    public int? StatusCode { get; set; }
    /// <summary>Final content type when available.</summary>
    public string? ContentType { get; set; }
    /// <summary>True when the URL returned a successful non-looping response.</summary>
    public bool Success { get; set; }
    /// <summary>True when at least one redirect was observed.</summary>
    public bool WasRedirected { get; set; }
    /// <summary>True when redirect processing detected a loop or exceeded the redirect limit.</summary>
    public bool RedirectLoop { get; set; }
    /// <summary>Number of redirect hops observed.</summary>
    public int RedirectHopCount { get; set; }
    /// <summary>True when X-Robots-Tag or meta robots marks the URL noindex.</summary>
    public bool NoIndex { get; set; }
    /// <summary>Canonical URL found in HTML when available.</summary>
    public string? CanonicalUrl { get; set; }
    /// <summary>True when the canonical URL differs from the final URL.</summary>
    public bool CanonicalMismatch { get; set; }
    /// <summary>Probe error when the URL could not be fetched.</summary>
    public string? Error { get; set; }
    /// <summary>Redirect chain including the starting URL.</summary>
    public List<string> RedirectChain { get; } = new();
}

/// <summary>Options controlling sitemap fetch, parsing, and URL probing.</summary>
public sealed class SitemapAnalysisOptions {
    /// <summary>Per-request timeout.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(20);
    /// <summary>When true, HTTP sitemap discovery is attempted after HTTPS candidates.</summary>
    public bool AllowHttpFallback { get; set; } = true;
    /// <summary>When true, sitemap URL entries are probed for reachability.</summary>
    public bool ProbeUrls { get; set; } = true;
    /// <summary>When true, successful HTML URL probes are inspected for noindex and canonical tags.</summary>
    public bool CheckCanonical { get; set; } = true;
    /// <summary>Maximum sitemap XML documents to fetch, including sitemapindex children.</summary>
    public int MaxSitemapDocuments { get; set; } = 20;
    /// <summary>Maximum URL entries to parse from sitemap urlsets.</summary>
    public int MaxEntries { get; set; } = 10000;
    /// <summary>Maximum parsed URLs to probe.</summary>
    public int MaxUrlProbes { get; set; } = 250;
    /// <summary>Maximum redirect hops before reporting a redirect loop.</summary>
    public int MaxRedirects { get; set; } = 10;
    /// <summary>Maximum sitemap XML response characters to read before parsing.</summary>
    public int MaxSitemapBodyCharacters { get; set; } = 20 * 1024 * 1024;
    /// <summary>When true, discovered sitemap documents and URL probes are limited to the analyzed origin host or matching www host.</summary>
    public bool RestrictRemoteFetchesToOriginHost { get; set; }
    /// <summary>User agent sent with sitemap and URL probes.</summary>
    public string UserAgent { get; set; } = "Mozilla/5.0 (compatible; DomainDetective-Sitemap)";
}
