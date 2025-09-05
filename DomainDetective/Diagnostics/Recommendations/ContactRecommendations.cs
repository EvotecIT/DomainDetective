using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class ContactRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[ContactCodes.RecordFound] = new RecommendationAdvice {
            Code = ContactCodes.RecordFound,
            Title = "contact record found",
            Why = "Publishing a contact TXT record makes it easier to reach administrators.",
            How = "Maintain a contact TXT record at contact.<domain> with up-to-date details.",
            Domain = RecommendationDomain.Other,
            Tags = new[] { "contact", "txt" },
            Impact = "Improves ability to reach responsible parties.",
            Effort = RecommendationEffort.Low,
            Verify = "TXT record exists at contact.<domain>."
        };
        map[ContactCodes.FieldsWellFormed] = new RecommendationAdvice {
            Code = ContactCodes.FieldsWellFormed,
            Title = "contact record fields well-formed",
            Why = "Well-formed key=value pairs allow automated parsing of contact details.",
            How = "Publish semicolon-delimited key=value pairs such as email=admin@example.com.",
            Domain = RecommendationDomain.Other,
            Tags = new[] { "contact", "fields" },
            Impact = "Consumers can parse contact details automatically.",
            Effort = RecommendationEffort.Low,
            Verify = "Fields parse as key=value pairs."
        };
    }
}
