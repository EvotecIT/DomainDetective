namespace DomainDetective.Providers.Email;

public enum DmarcSubdomainPolicyRecommendation
{
    None = 0,
    MatchParent = 1,
    Quarantine = 2,
    Reject = 3
}

