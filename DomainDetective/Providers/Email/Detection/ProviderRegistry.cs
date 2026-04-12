using System.Collections.Generic;

namespace DomainDetective.Providers.Email;

/// <summary>Provides provider registry functionality.</summary>
public static class ProviderRegistry
{
    private static readonly List<IMailProvider> _all = new()
    {
        new Vendors.Microsoft365Provider(),
        new Vendors.GoogleWorkspaceProvider(),
        new Vendors.MimecastProvider(),
        new Vendors.BarracudaEmailGatewayDefenseProvider(),
        new Vendors.ProofpointEssentialsProvider(),
        new Vendors.ZohoMailProvider(),
        new Vendors.SendGridProvider(),
        new Vendors.AmazonSesProvider(),
        new Vendors.MailgunProvider(),
        new Vendors.PostmarkProvider(),
        new Vendors.FastmailProvider(),
        new Vendors.ProtonMailProvider(),
        new Vendors.CloudflareEmailRoutingProvider(),
        new Vendors.CiscoSecureEmailProvider()
    };

    /// <summary>Represents the all value.</summary>
    public static IReadOnlyList<IMailProvider> All => _all;
}
