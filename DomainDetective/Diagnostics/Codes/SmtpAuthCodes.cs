namespace DomainDetective;

internal static class SmtpAuthCodes {
    public const string AuthWithout8BitMime = "SMTPAUTH.AuthWithout8BITMIME";
    public const string CheckFailed = "SMTPAUTH.Check.Failed";
    public const string AuthOverPlaintext = "SMTPAUTH.AuthOverPlaintext";
    public const string ObsoleteMechanism = "SMTPAUTH.ObsoleteMechanism";
    public const string NoStrongMechanism = "SMTPAUTH.NoStrongMechanism";
    public const string TlsRequired = "SMTPAUTH.TlsRequired";
    public const string StrongMechanism = "SMTPAUTH.StrongMechanism";
}
