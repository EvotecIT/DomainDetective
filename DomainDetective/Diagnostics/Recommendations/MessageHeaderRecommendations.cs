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
    }
}
