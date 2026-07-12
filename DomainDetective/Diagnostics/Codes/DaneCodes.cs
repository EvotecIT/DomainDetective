namespace DomainDetective;

internal static class DaneCodes {
    public const string NoRecords = "DANE.NoRecords";
    public const string UsageNotNumeric = "DANE.TLSA.Usage.NotNumeric";
    public const string UsageInvalid = "DANE.TLSA.Usage.Invalid";
    public const string SelectorNotNumeric = "DANE.TLSA.Selector.NotNumeric";
    public const string SelectorInvalid = "DANE.TLSA.Selector.Invalid";
    public const string MatchingTypeNotNumeric = "DANE.TLSA.MatchingType.NotNumeric";
    public const string MatchingTypeInvalid = "DANE.TLSA.MatchingType.Invalid";
    public const string RecordValid = "DANE.TLSA.RecordValid";
    public const string CertificateMatches = "DANE.TLSA.CertificateMatches";
    public const string CertificateMismatch = "DANE.TLSA.CertificateMismatch";
    public const string CertificateCheckFailed = "DANE.TLSA.CertificateCheckFailed";
    public const string DnssecNotValidated = "DANE.TLSA.DnssecNotValidated";
    public const string PkixNotValidated = "DANE.TLSA.PkixNotValidated";
    public const string ComboNotRecommended = "DANE.TLSA.Combo.NotRecommended";
    public const string AlignmentMissingForMx = "DANE.Alignment.MissingForMX";
    public const string AlignmentTlsWeak = "DANE.Alignment.TlsaPresentButTlsWeak";
}

