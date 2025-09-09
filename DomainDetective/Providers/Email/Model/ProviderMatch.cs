using System.Collections.Generic;

namespace DomainDetective.Providers.Email;

public sealed class ProviderMatch
{
    public IMailProvider? Primary { get; init; }
    public double PrimaryScore { get; init; }

    public List<IMailProvider> Gateways { get; } = new();
    public List<IMailProvider> OutboundSenders { get; } = new();
}
