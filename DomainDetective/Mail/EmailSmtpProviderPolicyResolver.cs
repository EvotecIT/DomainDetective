using System.Collections.Generic;
using DomainDetective.Providers.Email;

namespace DomainDetective;

/// <summary>Provides email smtp provider policy resolver functionality.</summary>
public static class EmailSmtpProviderPolicyResolver {
    private static readonly IReadOnlyDictionary<MailProviderKind, EmailSmtpProviderPolicy> _defaults =
        new Dictionary<MailProviderKind, EmailSmtpProviderPolicy> {
            { MailProviderKind.Microsoft365, new EmailSmtpProviderPolicy { Provider = MailProviderKind.Microsoft365, DisableCatchAll = true } },
            { MailProviderKind.GoogleWorkspace, new EmailSmtpProviderPolicy { Provider = MailProviderKind.GoogleWorkspace, DisableCatchAll = true } },
            { MailProviderKind.Mimecast, new EmailSmtpProviderPolicy { Provider = MailProviderKind.Mimecast, DisableCatchAll = true } },
            { MailProviderKind.BarracudaEmailGatewayDefense, new EmailSmtpProviderPolicy { Provider = MailProviderKind.BarracudaEmailGatewayDefense, DisableCatchAll = true } },
            { MailProviderKind.ProofpointEssentials, new EmailSmtpProviderPolicy { Provider = MailProviderKind.ProofpointEssentials, DisableCatchAll = true } },
            { MailProviderKind.CloudflareEmailRouting, new EmailSmtpProviderPolicy { Provider = MailProviderKind.CloudflareEmailRouting, DisableCatchAll = true } },
            { MailProviderKind.CiscoSecureEmail, new EmailSmtpProviderPolicy { Provider = MailProviderKind.CiscoSecureEmail, DisableCatchAll = true } },
            { MailProviderKind.ZohoMail, new EmailSmtpProviderPolicy { Provider = MailProviderKind.ZohoMail, DisableCatchAll = true } },
            { MailProviderKind.ProtonMail, new EmailSmtpProviderPolicy { Provider = MailProviderKind.ProtonMail, DisableCatchAll = true } }
        };

    /// <summary>Executes the resolve operation.</summary>
    public static EmailSmtpProviderPolicy? Resolve(MailProviderKind provider, EmailAddressValidationOptions options) {
        if (provider == MailProviderKind.Unknown || options == null) {
            return null;
        }

        if (options.ProviderPolicies != null && options.ProviderPolicies.TryGetValue(provider, out var overridePolicy)) {
            return overridePolicy;
        }

        if (_defaults.TryGetValue(provider, out var policy)) {
            return policy;
        }

        return null;
    }
}
