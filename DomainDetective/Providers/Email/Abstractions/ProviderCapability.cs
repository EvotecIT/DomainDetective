namespace DomainDetective.Providers.Email;

[System.Flags]
public enum ProviderCapability
{
    None = 0,
    InboundMx = 1,
    OutboundOnly = 2,
    Gateway = 4,
    DkimSigning = 8,
    SpfPublish = 16
}
