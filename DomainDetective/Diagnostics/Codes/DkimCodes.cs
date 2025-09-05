namespace DomainDetective;

internal static class DkimCodes {
    public const string KeyWeak = "DKIM.Key.Weak";
    public const string KeyOld = "DKIM.Key.Old";
    public const string HashDeprecated = "DKIM.Hash.Deprecated";
    public const string TagGDeprecated = "DKIM.Tag.G.Deprecated";
    public const string TagQDeprecated = "DKIM.Tag.Q.Deprecated";
    public const string AdspObsolete = "DKIM.ADSP.Obsolete";
    public const string KeyTooShort = "DKIM.Key.TooShort";
    public const string CanonicalizationUnknown = "DKIM.Canonicalization.Unknown";

    // Positive/posture signals
    public const string RecordPresent = "DKIM.Record.Present";
    public const string RecordStartsV1 = "DKIM.Record.StartsV1";
    public const string PublicKeyPresent = "DKIM.Key.Present";
    public const string KeyStrong = "DKIM.Key.Rsa2048Plus";
    public const string KeyTypeValid = "DKIM.KeyType.Valid";
    public const string CanonicalizationValid = "DKIM.Canonicalization.Valid";
    public const string HashSha256 = "DKIM.Hash.Sha256";
    public const string FlagsValid = "DKIM.Flags.Valid";
    public const string SignatureValid = "DKIM.Signature.Valid";
    public const string SelectorAligned = "DKIM.Selector.Aligned";
    public const string AlgorithmRecommended = "DKIM.Algorithm.Recommended";
    public const string KeyReused = "DKIM.Key.Reused";
    public const string QueryFailed = "DKIM.Query.Failed";
}
