namespace DomainDetective;

internal static class DnsPropagationCodes {
    public const string AsnMismatch = "DNSPROP.ASN.Mismatch";
    public const string NoServersSelected = "DNSPROP.Servers.None";
    public const string ResultsPresent = "DNSPROP.Results.Present";
    public const string QueryFailed = "DNSPROP.Query.Failed";
    public const string ErrorsPresent = "DNSPROP.Query.ErrorsPresent";
    public const string InconsistentAnswers = "DNSPROP.Answers.Inconsistent";
    public const string ConsistentAnswers = "DNSPROP.Answers.Consistent";
    public const string NonPublicIpAddress = "DNSPROP.IP.NonPublic";
    public const string SplitHorizonSuspected = "DNSPROP.SplitHorizon.Suspected";
}

