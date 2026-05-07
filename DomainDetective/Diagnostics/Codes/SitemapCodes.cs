namespace DomainDetective;

internal static class SitemapCodes {
    public const string Available = "SITEMAP.Available";
    public const string Missing = "SITEMAP.Missing";
    public const string DownloadFailed = "SITEMAP.Download.Failed";
    public const string XmlValid = "SITEMAP.Xml.Valid";
    public const string XmlInvalid = "SITEMAP.Xml.Invalid";
    public const string RootInvalid = "SITEMAP.Root.Invalid";
    public const string NamespaceInvalid = "SITEMAP.Namespace.Invalid";
    public const string UrlEntryPresent = "SITEMAP.UrlEntry.Present";
    public const string SitemapIndexPresent = "SITEMAP.Index.Present";
    public const string CrossHostSitemap = "SITEMAP.Document.CrossHost";
    public const string LocMissing = "SITEMAP.Loc.Missing";
    public const string LocInvalid = "SITEMAP.Loc.Invalid";
    public const string LocDuplicate = "SITEMAP.Loc.Duplicate";
    public const string LastModInvalid = "SITEMAP.LastMod.Invalid";
    public const string ChangeFrequencyInvalid = "SITEMAP.ChangeFrequency.Invalid";
    public const string PriorityInvalid = "SITEMAP.Priority.Invalid";
    public const string UrlOk = "SITEMAP.Url.OK";
    public const string UrlRedirect = "SITEMAP.Url.Redirect";
    public const string UrlRedirectLoop = "SITEMAP.Url.RedirectLoop";
    public const string UrlAccessForbidden = "SITEMAP.Url.AccessForbidden";
    public const string UrlClientError = "SITEMAP.Url.ClientError";
    public const string UrlServerError = "SITEMAP.Url.ServerError";
    public const string UrlFetchFailed = "SITEMAP.Url.FetchFailed";
    public const string UrlNoIndex = "SITEMAP.Url.NoIndex";
    public const string CanonicalMismatch = "SITEMAP.Canonical.Mismatch";
    public const string LimitReached = "SITEMAP.Limit.Reached";
}
