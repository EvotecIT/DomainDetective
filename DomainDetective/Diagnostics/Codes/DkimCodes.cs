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
}
