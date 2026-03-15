using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class Microsoft365Recommendations : IRecommendationProvider
{
    public void Register(IDictionary<string, RecommendationAdvice> map)
    {
        map[Microsoft365Codes.AuthUserEnumerationExposed] = new RecommendationAdvice
        {
            Code = Microsoft365Codes.AuthUserEnumerationExposed,
            Title = "Microsoft auth probe exposes account existence hints",
            Why = "A public GetCredentialType-style response that varies by account state can help attackers validate usernames before password spraying or phishing.",
            How = "Review Microsoft Entra ID authentication hardening, monitor sign-in abuse, validate smart lockout and risk policies, and minimize public identifiers where possible.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "microsoft365", "entra", "authentication", "enumeration" },
            Impact = "Improves attacker reconnaissance against the tenant's public sign-in surface.",
            Effort = RecommendationEffort.Medium,
            Verify = "Repeat the public probe and confirm the tenant's exposed auth behavior is understood and compensated for with monitoring and controls."
        };

        map[Microsoft365Codes.AuthManagedPostureDetected] = new RecommendationAdvice
        {
            Code = Microsoft365Codes.AuthManagedPostureDetected,
            Title = "Managed Microsoft authentication posture detected",
            Why = "A managed tenant posture usually means Microsoft handles the primary sign-in experience directly, which simplifies hardening and monitoring.",
            How = "Keep Conditional Access, MFA, and sign-in risk protections aligned with the managed tenant posture, and periodically review tenant-wide auth settings.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "microsoft365", "entra", "managed-auth" },
            Impact = "Confirms a simpler cloud-managed auth path for the tenant.",
            Effort = RecommendationEffort.Low,
            Verify = "OIDC discovery, GetUserRealm, and auth probe results should continue to align on managed/cloud-auth behavior."
        };

        map[Microsoft365Codes.AuthFederatedPostureDetected] = new RecommendationAdvice
        {
            Code = Microsoft365Codes.AuthFederatedPostureDetected,
            Title = "Federated Microsoft authentication posture detected",
            Why = "Federated sign-in increases dependency on external identity infrastructure and widens the critical auth surface beyond Microsoft-hosted endpoints.",
            How = "Review the federation service, certificates, redirect targets, and monitoring coverage, and make sure failover and incident procedures cover the external IdP path.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "microsoft365", "entra", "federation" },
            Impact = "Introduces additional auth dependencies and federation-specific failure modes.",
            Effort = RecommendationEffort.Medium,
            Verify = "Public auth probing should continue to show the expected federation redirect and tenant namespace posture."
        };

        map[Microsoft365Codes.AuthConsumerPostureDetected] = new RecommendationAdvice
        {
            Code = Microsoft365Codes.AuthConsumerPostureDetected,
            Title = "Consumer-style Microsoft identity posture detected",
            Why = "Consumer identity signals indicate the analyzed namespace is not behaving like a standard enterprise Microsoft 365 tenant.",
            How = "Confirm the domain is expected to map to a consumer Microsoft identity surface and document any differences from enterprise Entra ID assumptions.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "microsoft365", "consumer", "identity" },
            Impact = "Helps avoid applying enterprise-only assumptions to a consumer-oriented namespace.",
            Effort = RecommendationEffort.Low,
            Verify = "Tenant region and auth probe results should continue to indicate consumer identity handling."
        };

        map[Microsoft365Codes.AuthRedirectFlowDetected] = new RecommendationAdvice
        {
            Code = Microsoft365Codes.AuthRedirectFlowDetected,
            Title = "Redirect-based Microsoft sign-in flow detected",
            Why = "Redirect-based sign-in means the auth journey leaves the default Microsoft credential prompt and depends on a redirected identity path.",
            How = "Track the redirect target, validate its certificates and availability, and make sure federation or external IdP changes are monitored like production auth dependencies.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "microsoft365", "redirect", "identity" },
            Impact = "Auth resilience and trust now depend on the redirected sign-in path.",
            Effort = RecommendationEffort.Low,
            Verify = "The public auth probe should continue to return the expected federation redirect URL."
        };

        map[Microsoft365Codes.AuthNativeCredentialFlowDetected] = new RecommendationAdvice
        {
            Code = Microsoft365Codes.AuthNativeCredentialFlowDetected,
            Title = "Native Microsoft credential flow detected",
            Why = "A native credential flow suggests Microsoft-hosted credential collection is the primary sign-in path for the tenant.",
            How = "Keep Microsoft-hosted sign-in controls hardened with MFA, Conditional Access, and sign-in risk detection, and review legacy auth exposure regularly.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "microsoft365", "entra", "native-auth" },
            Impact = "Confirms the tenant primarily uses Microsoft's hosted credential experience.",
            Effort = RecommendationEffort.Low,
            Verify = "The auth probe should continue to indicate a non-redirect, native credential preference."
        };
    }
}
