using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck {
    /// <summary>
    /// Shares identical prerequisites within one Verify invocation. Tasks belong to the run,
    /// so a later run or a direct call always obtains fresh mutable analysis results.
    /// </summary>
    private void ConfigureSharedChecks(Dictionary<HealthCheckType, Func<Task>> actions,
        string domainName, CancellationToken cancellationToken) {
        var ns = new Lazy<Task>(() => VerifyNS(domainName, cancellationToken));
        var http = new Lazy<Task>(() => VerifyWebsiteHttps(domainName, cancellationToken));
        var certificate = new Lazy<Task>(() => VerifyWebsiteCertificate(domainName, cancellationToken: cancellationToken));
        actions[HealthCheckType.NS] = () => ns.Value;
        actions[HealthCheckType.DELEGATION] = async () => {
            await ns.Value.ConfigureAwait(false);
            await NSAnalysis.AnalyzeParentDelegation(domainName, _logger, cancellationToken).ConfigureAwait(false);
        };
        actions[HealthCheckType.HTTP] = () => http.Value;
        actions[HealthCheckType.CERT] = () => certificate.Value;
        actions[HealthCheckType.WEBSITE] = () => Task.WhenAll(http.Value, certificate.Value);
    }
}
