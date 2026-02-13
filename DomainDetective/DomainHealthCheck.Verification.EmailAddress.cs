using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck {
    /// <summary>
    /// Validates an email address with syntax, DNS, and optional SMTP/HTTP checks.
    /// </summary>
    public async Task VerifyEmailAddress(string emailAddress, EmailAddressValidationOptions? options = null, CancellationToken cancellationToken = default) {
        if (string.IsNullOrWhiteSpace(emailAddress)) {
            throw new ArgumentNullException(nameof(emailAddress));
        }
        EmailAddressValidationAnalysis.DnsConfiguration = DnsConfiguration;
        EmailAddressValidationAnalysis.HttpClientFactory = HttpClientFactory;
        await EmailAddressValidationAnalysis.AnalyzeAsync(emailAddress, options, _logger, cancellationToken);
    }
}
