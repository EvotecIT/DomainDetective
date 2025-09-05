using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class PortAvailabilityRecommendations : IRecommendationProvider
{
    public void Register(IDictionary<string, RecommendationAdvice> map)
    {
        map[PortAvailabilityCodes.HttpResponding] = new RecommendationAdvice
        {
            Code = PortAvailabilityCodes.HttpResponding,
            Title = "HTTP service responded",
            Why = "Expected HTTP service is reachable on port 80.",
            How = "No action required.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "http", "availability" },
            Impact = "Confirms web service availability.",
            Effort = RecommendationEffort.Low,
            Verify = "Fetch http://host/ to confirm response."
        };

        map[PortAvailabilityCodes.HttpsResponding] = new RecommendationAdvice
        {
            Code = PortAvailabilityCodes.HttpsResponding,
            Title = "HTTPS service responded",
            Why = "Expected HTTPS service is reachable on port 443.",
            How = "No action required.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "https", "availability" },
            Impact = "Confirms secure web service availability.",
            Effort = RecommendationEffort.Low,
            Verify = "Fetch https://host/ to confirm response."
        };

        map[PortAvailabilityCodes.SmtpResponding] = new RecommendationAdvice
        {
            Code = PortAvailabilityCodes.SmtpResponding,
            Title = "SMTP service responded",
            Why = "Expected SMTP service is reachable on port 25.",
            How = "No action required.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "smtp", "availability" },
            Impact = "Confirms mail server connectivity.",
            Effort = RecommendationEffort.Low,
            Verify = "Connect using telnet host 25 to confirm response."
        };

        map[PortAvailabilityCodes.SmtpsResponding] = new RecommendationAdvice
        {
            Code = PortAvailabilityCodes.SmtpsResponding,
            Title = "SMTPS service responded",
            Why = "Expected SMTPS service is reachable on port 465.",
            How = "No action required.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "smtps", "availability" },
            Impact = "Confirms secure mail submission service.",
            Effort = RecommendationEffort.Low,
            Verify = "Connect using openssl s_client -connect host:465."
        };

        map[PortAvailabilityCodes.SubmissionResponding] = new RecommendationAdvice
        {
            Code = PortAvailabilityCodes.SubmissionResponding,
            Title = "Submission service responded",
            Why = "Expected SMTP submission service is reachable on port 587.",
            How = "No action required.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "submission", "availability" },
            Impact = "Confirms authenticated mail submission service.",
            Effort = RecommendationEffort.Low,
            Verify = "Connect using telnet host 587 to confirm response."
        };
    }
}
