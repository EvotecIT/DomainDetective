namespace DomainDetective;

internal static class CnameCodes {
    public const string LoopDetected = "CNAME.Loop.Detected";
    public const string NoLoop = "CNAME.Loop.None";
    public const string TargetResolves = "CNAME.Target.Resolves";
    public const string TargetDoesNotResolve = "CNAME.Target.DoesNotResolve";
    public const string DnsLookupFailed = "CNAME.Dns.LookupFailed";
}
