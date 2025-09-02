using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Verifies Autodiscover for a domain using DNS hints and an Outlook-like HTTP flow.
        /// </summary>
        /// <remarks>
        /// This performs two coordinated analyses:
        /// - DNS: Queries <c>_autodiscover._tcp</c> SRV, <c>autoconfig.&lt;domain&gt;</c> CNAME and <c>autodiscover.&lt;domain&gt;</c> CNAME.
        /// - HTTP: Attempts Autodiscover endpoints in Outlook order (HTTPS GET→POST on subdomain/root, HTTP redirects, Outlook v2 JSON
        ///   discovery with follow-up POST, then HTTPS GET→POST on CNAME and SRV targets when present).
        /// The DNS results are passed into the HTTP analysis (SRV target/port and CNAME target) to improve coverage.
        /// If Autodiscover CNAME points to Microsoft 365 (outlook.com) but HTTP flow yields no valid XML/JSON, an advisory is logged
        /// suggesting possible TLS interception or SNI/network issues.
        /// </remarks>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyAutodiscover(string domainName, CancellationToken cancellationToken = default) {
            domainName = NormalizeDomain(domainName);
            AutodiscoverAnalysis = new AutodiscoverAnalysis {
                DnsConfiguration = DnsConfiguration
            };
            await AutodiscoverAnalysis.Analyze(domainName, DnsConfiguration, _logger, cancellationToken);
            AutodiscoverHttpAnalysis = new AutodiscoverHttpAnalysis {
                SrvTarget = AutodiscoverAnalysis.SrvTarget,
                SrvPort = AutodiscoverAnalysis.SrvPort == 0 ? null : AutodiscoverAnalysis.SrvPort,
                CnameTarget = AutodiscoverAnalysis.AutodiscoverTarget,
                EmailForPost = null // default to autodiscover@domain
            };
            await AutodiscoverHttpAnalysis.Analyze(domainName, _logger, cancellationToken);
            AutodiscoverAnalysis.SetHttpEndpoints(AutodiscoverHttpAnalysis.Endpoints);

            // Advisory: If CNAME points to Outlook/M365 but HTTP flow didn't yield valid XML, hint at network/SNI issues
            try {
                var target = AutodiscoverAnalysis.AutodiscoverTarget ?? string.Empty;
                var endpoints = AutodiscoverHttpAnalysis?.Endpoints ?? Array.Empty<AutodiscoverEndpointResult>();
                var anyValid = System.Linq.Enumerable.Any(endpoints, e => e.XmlValid || e.JsonValid);
                if (AutodiscoverAnalysis.AutodiscoverCnameExists &&
                    (target.IndexOf("outlook.com", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
                     target.IndexOf("office365.com", System.StringComparison.OrdinalIgnoreCase) >= 0) &&
                    !anyValid)
                {
                    using var _collector = AssessmentCollector.ForAnalysis(_logger, AutodiscoverAnalysis, category: "Autodiscover", target: domainName);
                    _logger?.WriteWarningCode(AutodiscoverCodes.Office365FlowFailed, "Autodiscover CNAME targets Outlook, but HTTP Autodiscover did not return valid XML.");
                }
            } catch { }
        }
    }
}
