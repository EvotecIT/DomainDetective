using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>Analyzes DNS logs for tunneling patterns.</summary>
        public void CheckDnsTunneling(string domainName, CancellationToken ct = default) {
            CheckDnsTunnelingAsync(domainName, ct).GetAwaiter().GetResult();
        }

        /// <summary>Executes the check dns tunneling async operation.</summary>
        public async Task CheckDnsTunnelingAsync(string domainName, CancellationToken ct = default) {
            ct.ThrowIfCancellationRequested();
            var lines = DnsTunnelingLogs ?? Array.Empty<string>();
            await Task.Run(() => DnsTunnelingAnalysis.Analyze(domainName, lines), ct);
        }
    }
}
