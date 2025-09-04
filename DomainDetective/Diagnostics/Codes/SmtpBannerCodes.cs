namespace DomainDetective;

internal static class SmtpBannerCodes {
    public const string Truncated = "SMTPBANNER.Length.Truncated";
    public const string FormatInvalid = "SMTPBANNER.Format.Invalid";
    public const string CheckFailed = "SMTPBANNER.Check.Failed";
    public const string MissingDomain = "SMTPBANNER.Domain.Missing";
    public const string Not220 = "SMTPBANNER.Greeting.Not220";
    public const string VersionLeaked = "SMTPBANNER.Banner.VersionLeaked";
    public const string UnexpectedSoftware = "SMTPBANNER.Software.Unexpected";
    public const string HostnameMatch = "SMTPBANNER.Hostname.Match";
    public const string TlsAdvertised = "SMTPBANNER.TLS.Advertised";
}
