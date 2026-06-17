using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class MessageHeaderRecommendations : IRecommendationProvider
{
    public void Register(IDictionary<string, RecommendationAdvice> map)
    {
        map[MessageHeaderCodes.DkimPass] = new RecommendationAdvice
        {
            Code = MessageHeaderCodes.DkimPass,
            Title = "DKIM authentication passed",
            Why = "A valid DKIM signature confirms the message was authorized by the sending domain.",
            How = "Continue monitoring DKIM results and rotate keys regularly.",
            Links = new[] { "https://datatracker.ietf.org/doc/html/rfc6376" },
            Domain = RecommendationDomain.Dkim,
            Tags = new[] { "dkim", "email", "authentication" }
        };
        map[MessageHeaderCodes.SpfPass] = new RecommendationAdvice
        {
            Code = MessageHeaderCodes.SpfPass,
            Title = "SPF authentication passed",
            Why = "Passing SPF verifies the sending host was permitted to send on behalf of the domain.",
            How = "Maintain accurate SPF records for all sending services.",
            Links = new[] { "https://datatracker.ietf.org/doc/html/rfc7208" },
            Domain = RecommendationDomain.Spf,
            Tags = new[] { "spf", "email", "authentication" }
        };
        map[MessageHeaderCodes.DmarcPass] = new RecommendationAdvice
        {
            Code = MessageHeaderCodes.DmarcPass,
            Title = "DMARC alignment passed",
            Why = "Successful DMARC alignment improves deliverability and protects against spoofing.",
            How = "Monitor DMARC reports and maintain alignment of SPF and DKIM.",
            Links = new[] { "https://datatracker.ietf.org/doc/html/rfc7489" },
            Domain = RecommendationDomain.Dmarc,
            Tags = new[] { "dmarc", "email", "authentication" }
        };
        map[MessageHeaderCodes.ArcPass] = new RecommendationAdvice
        {
            Code = MessageHeaderCodes.ArcPass,
            Title = "ARC chain validated",
            Why = "A valid ARC chain preserves authentication results through forwarding services.",
            How = "Ensure intermediaries correctly sign and relay ARC headers.",
            Links = new[] { "https://datatracker.ietf.org/doc/html/rfc8617" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new[] { "arc", "email", "authentication" }
        };
        map[MessageHeaderCodes.DirectToExchangeOnlineObserved] = new RecommendationAdvice
        {
            Code = MessageHeaderCodes.DirectToExchangeOnlineObserved,
            Title = "Direct Exchange Online ingress observed",
            Why = "The message appears to have reached Exchange Online directly instead of first passing through the expected mail security gateway.",
            How = "Restrict inbound Exchange Online connectors to the approved gateway source IPs or certificate identity, and verify direct MX/EOP delivery is rejected.",
            Links = new[] { "https://learn.microsoft.com/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/inbound-connector" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new[] { "exchange-online", "mail-flow", "gateway", "headers" }
        };
        map[MessageHeaderCodes.AuthenticationFailedDeliveredToInbox] = new RecommendationAdvice
        {
            Code = MessageHeaderCodes.AuthenticationFailedDeliveredToInbox,
            Title = "Authentication failed but message reached Inbox",
            Why = "Inbox delivery with SPF, DKIM, or DMARC failure can make spoofed validation messages look normal to recipients.",
            How = "Review anti-spam policy actions, DMARC handling, SCL overrides, safe sender bypasses, and inbound connector attribution.",
            Links = new[] { "https://learn.microsoft.com/defender-office-365/email-authentication-about" },
            Domain = RecommendationDomain.Dmarc,
            Tags = new[] { "dmarc", "spf", "dkim", "inbox", "headers" }
        };
        map[MessageHeaderCodes.SelfSpoofDeliveredToInbox] = new RecommendationAdvice
        {
            Code = MessageHeaderCodes.SelfSpoofDeliveredToInbox,
            Title = "Same-domain self-spoof reached Inbox",
            Why = "A message using the recipient domain in the From header reached Inbox, which can undermine user trust cues and external tagging.",
            How = "Block unauthenticated same-domain inbound mail unless it arrives from trusted gateways or authenticated internal systems.",
            Links = new[] { "https://learn.microsoft.com/defender-office-365/anti-spoofing-protection-about" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new[] { "spoofing", "self-spoof", "exchange-online", "headers" }
        };
        map[MessageHeaderCodes.GatewayLoopDetected] = new RecommendationAdvice
        {
            Code = MessageHeaderCodes.GatewayLoopDetected,
            Title = "Gateway loop detected in headers",
            Why = "Headers show the message moving between Exchange Online and a third-party gateway, which may hide the original source or change authentication interpretation.",
            How = "Validate connector ordering, Enhanced Filtering for Connectors, and gateway reinjection rules so the original external source remains visible.",
            Links = new[] { "https://learn.microsoft.com/defender-office-365/enhanced-filtering-for-connectors" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new[] { "exchange-online", "gateway", "proofpoint", "headers" }
        };
        map[MessageHeaderCodes.ExpectedMxBypassed] = new RecommendationAdvice
        {
            Code = MessageHeaderCodes.ExpectedMxBypassed,
            Title = "Expected MX path was bypassed",
            Why = "The supplied public MX hosts were not observed in the message path while direct Exchange Online ingress was detected.",
            How = "Compare public MX, accepted domains, connector restrictions, and direct EOP/onmicrosoft delivery behavior, then enforce gateway-only ingress.",
            Links = new[] { "https://learn.microsoft.com/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/inbound-connector" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new[] { "mx", "gateway", "exchange-online", "headers" }
        };
    }
}
