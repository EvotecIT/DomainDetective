using System.Threading;
using System.Threading.Tasks;
using DomainDetective.CLI;

namespace DomainDetective.CLI.Tests;

public class TestCliCancellation
{
    [Fact]
    public async Task RunChecks_HandlesUserCancellation()
    {
        using var cts = new CancellationTokenSource(100);
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await CommandUtilities.RunChecks(
                ["example.com"],
                null,
                checkHttp: false,
                checkWeb: false,
                checkTakeover: false,
                autodiscoverEndpoints: false,
                outputJson: false,
                summaryOnly: false,
                subdomainPolicy: false,
                unicodeOutput: false,
                danePorts: null,
                showProgress: true,
                skipRevocation: false,
                portScanProfiles: null,
                cts.Token));
    }
}
