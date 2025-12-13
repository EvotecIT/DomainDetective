namespace DomainDetective.Providers.Email;

public sealed class ProviderEvidence
{
    public ProviderEvidence(string providerId, string displayName, double score)
    {
        ProviderId = providerId;
        DisplayName = displayName;
        Score = score;
    }

    public string ProviderId { get; }
    public string DisplayName { get; }
    public double Score { get; }
}
