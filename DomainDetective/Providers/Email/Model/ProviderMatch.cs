using System.Collections.Generic;

namespace DomainDetective.Providers.Email;

/// <summary>Provides provider match functionality.</summary>
public sealed class ProviderMatch
{
    /// <summary>Gets or sets the primary value.</summary>
    public IMailProvider? Primary { get; init; }
    /// <summary>Gets or sets the primary score value.</summary>
    public double PrimaryScore { get; init; }

    /// <summary>Gets the gateways value.</summary>
    public List<IMailProvider> Gateways { get; } = new();
    /// <summary>Gets the outbound senders value.</summary>
    public List<IMailProvider> OutboundSenders { get; } = new();
}
