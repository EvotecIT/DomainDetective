using DomainDetective.Providers.Email;
using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestEmailSmtpProviderPolicyResolver {
    [Fact]
    public void DefaultPolicyDisablesCatchAllForMajorProviders() {
        var options = new EmailAddressValidationOptions();

        var policy = EmailSmtpProviderPolicyResolver.Resolve(MailProviderKind.Microsoft365, options);

        Assert.NotNull(policy);
        Assert.True(policy!.DisableCatchAll);
    }

    [Fact]
    public void CustomPolicyOverridesDefaults() {
        var options = new EmailAddressValidationOptions {
            ProviderPolicies = new Dictionary<MailProviderKind, EmailSmtpProviderPolicy> {
                {
                    MailProviderKind.Microsoft365,
                    new EmailSmtpProviderPolicy {
                        Provider = MailProviderKind.Microsoft365,
                        DisableCatchAll = false,
                        SmtpPortOverride = 2525
                    }
                }
            }
        };

        var policy = EmailSmtpProviderPolicyResolver.Resolve(MailProviderKind.Microsoft365, options);

        Assert.NotNull(policy);
        Assert.False(policy!.DisableCatchAll);
        Assert.Equal(2525, policy.SmtpPortOverride);
    }
}
