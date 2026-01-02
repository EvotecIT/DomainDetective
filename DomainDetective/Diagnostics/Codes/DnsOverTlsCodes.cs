namespace DomainDetective;

internal static class DnsOverTlsCodes
{
    public const string Supported = "DNSOVERTLS.Supported";
    public const string NotSupported = "DNSOVERTLS.NotSupported";
    public const string ProbeFailed = "DNSOVERTLS.Probe.Failed";
    public const string CertificateMismatch = "DNSOVERTLS.Certificate.HostnameMismatch";
    public const string CertificateInvalid = "DNSOVERTLS.Certificate.Invalid";
    public const string NameServersMissing = "DNSOVERTLS.NS.Missing";
    public const string NameServerAddressesMissing = "DNSOVERTLS.NS.NoAddresses";
}

