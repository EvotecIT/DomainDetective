namespace DomainDetective;

internal static class MtaStsCodes {
    public const string FetchFailed = "MTASTS.Fetch.Failed";
    public const string MissingRecord = "MTASTS.Record.Missing";
    public const string PolicyInvalid = "MTASTS.Policy.Invalid";
    public const string NotEnforcing = "MTASTS.Policy.NotEnforcing";
    public const string Enforced = "MTASTS.Policy.Enforced";
    public const string PolicyValid = "MTASTS.Policy.Valid";
    public const string HttpsAvailable = "MTASTS.Https.Available";
    public const string MxNotAligned = "MTASTS.MX.NotAligned";
    public const string MaxAgeLow = "MTASTS.MaxAge.Low";
    public const string MxStartTlsMissing = "MTASTS.MX.STARTTLS.Missing";
    public const string MxTlsWeak = "MTASTS.MX.TLS.Weak";
    public const string MxTlsModernAll = "MTASTS.MX.TLS.ModernAll";
    public const string ProviderRecommended = "MTASTS.Provider.Recommended";
}
