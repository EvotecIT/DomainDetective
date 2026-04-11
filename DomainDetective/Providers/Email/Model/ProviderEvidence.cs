namespace DomainDetective.Providers.Email;

/// <summary>Provides provider evidence functionality.</summary>
public sealed class ProviderEvidence
{
    /// <summary>Initializes a new instance of the ProviderEvidence class.</summary>
    public ProviderEvidence(string providerId, string displayName, double score)
    {
        ProviderId = providerId;
        DisplayName = displayName;
        Score = score;
    }

    /// <summary>Gets the provider id value.</summary>
    public string ProviderId { get; }
    /// <summary>Gets the display name value.</summary>
    public string DisplayName { get; }
    /// <summary>Gets the score value.</summary>
    public double Score { get; }
}
