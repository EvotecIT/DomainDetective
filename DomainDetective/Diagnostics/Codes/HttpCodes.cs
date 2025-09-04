namespace DomainDetective;

internal static class HttpCodes {
    public const string Http3Downgrade = "HTTP.H3.Downgrade";
    public const string H3AltSvcMismatch = "HTTP.H3.AltSvcMismatch";
    public const string HpkpDeprecated = "HTTP.HPKP.Deprecated";
    public const string DnsLookupFailed = "HTTP.DNS.LookupFailed";
    public const string RequestFailed = "HTTP.Request.Failed";
    public const string Timeout = "HTTP.Request.Timeout";
    public const string CheckFailed = "HTTP.Check.Failed";
    public const string HstsMissing = "HTTP.HSTS.Missing";
    public const string HstsTooShort = "HTTP.HSTS.TooShort";
    public const string HstsUnknownDirective = "HTTP.HSTS.UnknownDirective";
    public const string MixedContent = "HTTP.MixedContent.Detected";
    public const string CspUnsafe = "HTTP.CSP.UnsafeDirectives";
    public const string XssProtectionDeprecated = "HTTP.XSSProtection.Deprecated";
    public const string ExpectCtDeprecated = "HTTP.ExpectCT.Deprecated";
    public const string CspReportOnly = "HTTP.CSP.ReportOnly";
    public const string PermissionsPolicyWeak = "HTTP.Header.Weak.PermissionsPolicy";
    public const string COOPWeak = "HTTP.Header.Weak.COOP";
    public const string COEPWeak = "HTTP.Header.Weak.COEP";
    public const string CORPWeak = "HTTP.Header.Weak.CORP";
    public const string MissingHeaderCsp = "HTTP.Header.Missing.CSP";
    public const string MissingHeaderReferrerPolicy = "HTTP.Header.Missing.ReferrerPolicy";
    public const string MissingHeaderXFrameOptions = "HTTP.Header.Missing.XFrameOptions";
    public const string MissingHeaderPermissionsPolicy = "HTTP.Header.Missing.PermissionsPolicy";
    public const string MissingHeaderXContentTypeOptions = "HTTP.Header.Missing.XContentTypeOptions";
    public const string MissingHeaderCOOP = "HTTP.Header.Missing.COOP";
    public const string MissingHeaderCOEP = "HTTP.Header.Missing.COEP";
    public const string MissingHeaderCORP = "HTTP.Header.Missing.CORP";
    public const string MissingHeaderOAC = "HTTP.Header.Missing.OAC";
    public const string MissingHeaderXPermittedCrossDomainPolicies = "HTTP.Header.Missing.XPermittedCrossDomainPolicies";
    public const string InsecureFormAction = "HTTP.Forms.InsecureAction";
    public const string XFrameOptionsInvalid = "HTTP.XFO.InvalidValue";
    public const string XContentTypeOptionsInvalid = "HTTP.XCTO.InvalidValue";
    // Positive/presence signals to enrich datasets
    public const string SecureRedirect = "HTTP.Redirect.ToHTTPS";
    public const string HstsPresent = "HTTP.HSTS.Present";
    public const string CspPresent = "HTTP.CSP.Present";
    public const string ReferrerPolicyPresent = "HTTP.Header.Present.ReferrerPolicy";
    public const string XFrameOptionsPresent = "HTTP.Header.Present.XFrameOptions";
    public const string XContentTypeOptionsPresent = "HTTP.Header.Present.XContentTypeOptions";
    public const string PermissionsPolicyPresent = "HTTP.Header.Present.PermissionsPolicy";
    public const string COOPPresent = "HTTP.Header.Present.COOP";
    public const string COEPPresent = "HTTP.Header.Present.COEP";
    public const string CORPPresent = "HTTP.Header.Present.CORP";
    public const string OACEnabled = "HTTP.OAC.Enabled";
}
