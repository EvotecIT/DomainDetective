namespace DomainDetective;

internal static class TlsRptCodes {
    public const string MissingRua = "TLSRPT.RUA.Missing";
    public const string RuaHttpUnreachable = "TLSRPT.RUA.Http.Unreachable";
    public const string RuaHttpError = "TLSRPT.RUA.Http.Error";
    public const string RecordPresent = "TLSRPT.Record.Present";
    public const string RecordStartsV1 = "TLSRPT.Record.StartsV1";
    public const string RuaMailtoPresent = "TLSRPT.RUA.Mailto.Present";
    public const string RuaHttpPresent = "TLSRPT.RUA.Http.Present";
    public const string PolicyValid = "TLSRPT.Policy.Valid";
}

