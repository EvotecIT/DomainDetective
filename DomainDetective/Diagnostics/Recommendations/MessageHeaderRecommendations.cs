using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class MessageHeaderRecommendations : IRecommendationProvider
{
    public void Register(IDictionary<string, RecommendationAdvice> map)
    {
        map[MessageHeaderCodes.DkimPass] = new RecommendationAdvice
        {
            Code = MessageHeaderCodes.DkimPass,
            Title = "Receiver reports DKIM pass",
            Why = "The selected Authentication-Results field reports a pass. Its provenance and gateway sanitization determine whether that claim is authoritative.",
            How = "Review the selected authserv-id and trust level; verify the original MIME message when independent cryptographic evidence is needed.",
            Links = new[] { "https://datatracker.ietf.org/doc/html/rfc6376" },
            Domain = RecommendationDomain.Dkim,
            Tags = new[] { "dkim", "email", "authentication" }
        };
        map[MessageHeaderCodes.SpfPass] = new RecommendationAdvice
        {
            Code = MessageHeaderCodes.SpfPass,
            Title = "Receiver reports SPF pass",
            Why = "The selected receiver reports that its observed sending host passed SPF. Headers alone do not reproduce the original SMTP session or delivery-time DNS.",
            How = "Confirm receiver provenance and inspect the reported envelope identity and its alignment with From.",
            Links = new[] { "https://datatracker.ietf.org/doc/html/rfc7208" },
            Domain = RecommendationDomain.Spf,
            Tags = new[] { "spf", "email", "authentication" }
        };
        map[MessageHeaderCodes.DmarcPass] = new RecommendationAdvice
        {
            Code = MessageHeaderCodes.DmarcPass,
            Title = "Receiver reports DMARC pass",
            Why = "The selected receiver reports DMARC pass; this is an authentication observation with the displayed provenance.",
            How = "Confirm gateway trust and review SPF/DKIM identities and alignment alongside DMARC aggregate reports.",
            Links = new[] { "https://datatracker.ietf.org/doc/html/rfc7489" },
            Domain = RecommendationDomain.Dmarc,
            Tags = new[] { "dmarc", "email", "authentication" }
        };
        map[MessageHeaderCodes.ArcPass] = new RecommendationAdvice
        {
            Code = MessageHeaderCodes.ArcPass,
            Title = "Receiver reports ARC pass",
            Why = "The selected receiver reports ARC pass. This is separate from local structure checks, cryptographic verification, and trust in the sealers.",
            How = "Verify the original MIME message and assess the forwarding services before relying on their authentication claims.",
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
