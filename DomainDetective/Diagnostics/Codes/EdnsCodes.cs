namespace DomainDetective;

internal static class EdnsCodes {
    public const string NotSupported = "EDNS.Server.NotSupported";
    public const string BufferTooLarge = "EDNS.BufferTooLarge";
    public const string TruncatedFallback = "EDNS.Truncated.FallbackTcp";
    public const string CookiesNotSupported = "EDNS.Cookie.NotSupported";

    // Positive/posture signals
    public const string Supported = "EDNS.Server.Supported";
    public const string UdpSizeOk = "EDNS.Buffer.Within1232";
    public const string VersionZero = "EDNS.Version.0";
    public const string CookiesSupported = "EDNS.Cookie.Supported";
}
