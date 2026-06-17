namespace DomainDetective;

internal static class MessageHeaderCodes {
    public const string MimeParseFailed = "HEADERS.Mime.ParseFailed";
    public const string ParseFailed = "HEADERS.Parse.Failed";
    public const string MalformedLine = "HEADERS.Line.Malformed";
    public const string DkimPass = "HEADERS.DKIM.Pass";
    public const string SpfPass = "HEADERS.SPF.Pass";
    public const string DmarcPass = "HEADERS.DMARC.Pass";
    public const string ArcPass = "HEADERS.ARC.Pass";
    public const string DirectToExchangeOnlineObserved = "HEADERS.Route.DirectToExchangeOnline";
    public const string AuthenticationFailedDeliveredToInbox = "HEADERS.Route.AuthFailedDeliveredToInbox";
    public const string SelfSpoofDeliveredToInbox = "HEADERS.Route.SelfSpoofDeliveredToInbox";
    public const string GatewayLoopDetected = "HEADERS.Route.GatewayLoopDetected";
    public const string ExpectedMxBypassed = "HEADERS.Route.ExpectedMxBypassed";
}

