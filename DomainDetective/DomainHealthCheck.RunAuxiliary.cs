using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck {
    private List<Task> StartAuxiliaryChecks(string domainName, HealthCheckExecutionOptions options, CancellationToken cancellationToken) {
        var tasks = new List<Task>();
        if (options.IncludePlainHttp) {
            VerificationPlainHttpCompleted = false;
            PlainHttpAnalysis.Subject = new UriBuilder($"http://{domainName}").Uri.GetLeftPart(UriPartial.Authority);
            tasks.Add(RunAdmittedCheckAsync(async () => {
                await PlainHttpAnalysis.AnalyzeUrl(PlainHttpAnalysis.Subject!, false, _logger, cancellationToken: cancellationToken).ConfigureAwait(false);
                VerificationPlainHttpCompleted = true;
            }, cancellationToken, "PLAIN HTTP"));
        }
        if (options.IncludeTakeoverCname) {
            VerificationTakeoverCompleted = false;
            tasks.Add(RunAdmittedCheckAsync(async () => {
                await VerifyTakeoverCname(domainName, cancellationToken).ConfigureAwait(false);
                VerificationTakeoverCompleted = true;
            }, cancellationToken, "TAKEOVER"));
        }
        return tasks;
    }
}
