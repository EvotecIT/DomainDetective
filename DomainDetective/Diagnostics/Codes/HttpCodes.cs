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
}
