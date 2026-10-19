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
        string domainName, CancellationToken cancellationToken, HealthCheckExecutionOptions options) {
        var childReady = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var ns = new Lazy<Task>(async () => {
            try { await VerifyNameServersAsync(domainName, cancellationToken, () => childReady.TrySetResult(true)).ConfigureAwait(false); }
            finally { childReady.TrySetResult(true); }
        });
        var website = new Lazy<Uri>(() => {
            ValidatePort(options.WebsitePort);
            var uri = new Uri($"https://{domainName}");
            return options.WebsitePort != 443 || uri.IsDefaultPort
                ? EndpointHostNormalizer.WithPort(uri, options.WebsitePort) : uri;
        });
        var http = new Lazy<Task>(() => VerifyWebsiteHttps(EndpointHostNormalizer.FormatUriAuthority(website.Value), cancellationToken));
        var certificate = new Lazy<Task>(() => VerifyWebsiteCertificate($"https://{EndpointHostNormalizer.FormatUriAuthority(website.Value)}", website.Value.Port, cancellationToken));
        actions[HealthCheckType.NS] = () => ns.Value;
        actions[HealthCheckType.DELEGATION] = async () => {
            var child = RunPrerequisiteAsync(HealthCheckType.NS, domainName, () => ns.Value);
            async Task ParentAsync() {
                await childReady.Task.WaitWithCancellation(cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                await RunAdmittedCheckAsync(() => NSAnalysis.AnalyzeParentDelegation(domainName, _logger, cancellationToken), cancellationToken).ConfigureAwait(false);
            }
            await Task.WhenAll(child, ParentAsync()).ConfigureAwait(false);
        };
        actions[HealthCheckType.HTTP] = () => http.Value;
        actions[HealthCheckType.CERT] = () => certificate.Value;
        actions[HealthCheckType.WEBSITE] = () => Task.WhenAll(
            RunPrerequisiteAsync(HealthCheckType.HTTP, domainName, () => http.Value),
            RunPrerequisiteAsync(HealthCheckType.CERT, domainName, () => certificate.Value));
    }
}
