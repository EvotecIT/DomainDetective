namespace DomainDetective.Providers.Email;

/// <summary>Defines values for provider capability.</summary>
[System.Flags]
public enum ProviderCapability
{
    /// <summary>Represents the none value.</summary>
    None = 0,
    /// <summary>Represents the inbound mx value.</summary>
    InboundMx = 1,
    /// <summary>Represents the outbound only value.</summary>
    OutboundOnly = 2,
    /// <summary>Represents the gateway value.</summary>
    Gateway = 4,
    /// <summary>Represents the dkim signing value.</summary>
    DkimSigning = 8,
    /// <summary>Represents the spf publish value.</summary>
    SpfPublish = 16
}
