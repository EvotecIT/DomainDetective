namespace DomainDetective;

internal static class SecurityTxtCodes {
    public const string SignatureVerifyFailed = "SECURITYTXT.Signature.VerifyFailed";
    public const string InvalidEmail = "SECURITYTXT.Contact.InvalidEmail";
    public const string InvalidUriScheme = "SECURITYTXT.Contact.InvalidUriScheme";
    public const string InvalidContactFormat = "SECURITYTXT.Contact.InvalidFormat";
    public const string MultipleExpires = "SECURITYTXT.Multiple.Expires";
    public const string MultipleSignatureEncryption = "SECURITYTXT.Multiple.SignatureEncryption";
    public const string MissingContact = "SECURITYTXT.Missing.Contact";
    public const string MissingExpires = "SECURITYTXT.Missing.Expires";
    public const string InvalidExpiresFormat = "SECURITYTXT.Expires.InvalidFormat";
    public const string ExpiresPast = "SECURITYTXT.Expires.Past";
    public const string ExpiresTooFarFuture = "SECURITYTXT.Expires.TooFarFuture";
    public const string CanonicalNotHttps = "SECURITYTXT.Canonical.NotHttps";
    public const string CanonicalMismatch = "SECURITYTXT.Canonical.Mismatch";
    public const string InvalidFile = "SECURITYTXT.Invalid.File";

    // Positive/posture signals
    public const string RecordPresent = "SECURITYTXT.Record.Present";
    public const string RecordValid = "SECURITYTXT.Record.Valid";
}
