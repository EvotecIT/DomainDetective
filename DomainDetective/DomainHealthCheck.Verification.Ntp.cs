using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>Queries an NTP server for clock information.</summary>
        /// <param name="host">Target server host name or IP.</param>
        /// <param name="port">NTP port number.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public Task TestNtpServer(string host, int port = 123, CancellationToken cancellationToken = default) =>
            CompleteDirectCheckAsync(HealthCheckType.NTP, () => TestNtpServerDirectCore(host, port, cancellationToken), cancellationToken, ownerDomain: host);

        private async Task TestNtpServerDirectCore(string host, int port = 123, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            await NtpAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>Queries a predefined NTP server.</summary>
        /// <param name="server">Built-in server enumeration.</param>
        /// <param name="port">NTP port number.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public Task TestNtpServer(NtpServer server, int port = 123, CancellationToken cancellationToken = default) =>
            CompleteDirectCheckAsync(HealthCheckType.NTP, () => TestNtpServerDirectCore(server, port, cancellationToken), cancellationToken);

        private Task TestNtpServerDirectCore(NtpServer server, int port = 123, CancellationToken cancellationToken = default) =>
            TestNtpServer(server.ToHost(), port, cancellationToken);
    }
}
