using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class MailClassificationRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[MailClassificationCodes.SendingAndReceiving] = new RecommendationAdvice {
            Code = MailClassificationCodes.SendingAndReceiving,
            Title = "Domain supports sending and receiving mail",
            Why = "Domain authorizes outbound mail and accepts inbound delivery.",
            How = "Maintain current authentication and delivery configurations.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new[] { "classification", "email" }
        };
        map[MailClassificationCodes.ReceivingOnly] = new RecommendationAdvice {
            Code = MailClassificationCodes.ReceivingOnly,
            Title = "Domain configured to receive mail only",
            Why = "Inbound delivery is enabled but no sending authorization was found.",
            How = "No action needed if intentional; add SPF/DKIM if outbound mail is required.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new[] { "classification", "email" }
        };
        map[MailClassificationCodes.SendingOnly] = new RecommendationAdvice {
            Code = MailClassificationCodes.SendingOnly,
            Title = "Domain configured to send mail only",
            Why = "Domain authorizes sending but does not advertise inbound mail servers.",
            How = "Maintain SPF/DKIM records; publish MX if inbound mail should be accepted.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new[] { "classification", "email" }
        };
        map[MailClassificationCodes.Parked] = new RecommendationAdvice {
            Code = MailClassificationCodes.Parked,
            Title = "Domain explicitly parked for email",
            Why = "Null MX and absence of sending signals indicate the domain is not used for email.",
            How = "No action required unless email service will be introduced.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new[] { "classification", "email" }
        };
    }
}
