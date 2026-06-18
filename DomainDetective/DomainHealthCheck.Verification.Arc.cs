using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Parses raw message headers.
        /// </summary>
        /// <param name="rawHeaders">Unparsed header text.</param>
        /// <param name="ct">Token to cancel the operation.</param>
        /// <returns>Populated <see cref="MessageHeaderAnalysis"/> instance.</returns>
        public MessageHeaderAnalysis CheckMessageHeaders(string rawHeaders, CancellationToken ct = default) {
            ct.ThrowIfCancellationRequested();

            var analysis = new MessageHeaderAnalysis();
            analysis.Parse(rawHeaders, _logger);
            return analysis;
        }

        /// <summary>
        /// Parses raw message headers and compares the observed route with expected public MX hosts.
        /// </summary>
        /// <param name="rawHeaders">Unparsed header text.</param>
        /// <param name="expectedMxHosts">Public MX hosts expected to process inbound mail.</param>
        /// <param name="ct">Token to cancel the operation.</param>
        /// <returns>Populated <see cref="MessageHeaderAnalysis"/> instance.</returns>
        public MessageHeaderAnalysis CheckMessageHeaders(string rawHeaders, IEnumerable<string>? expectedMxHosts, CancellationToken ct = default) {
            ct.ThrowIfCancellationRequested();

            var analysis = new MessageHeaderAnalysis();
            analysis.Parse(rawHeaders, _logger, emitRouteDiagnostics: false);
            analysis.CompareExpectedMx(expectedMxHosts, _logger);
            return analysis;
        }

        /// <summary>
        /// Validates ARC headers contained in <paramref name="rawHeaders"/>.
        /// </summary>
        /// <param name="rawHeaders">Raw message headers.</param>
        /// <param name="ct">Token to cancel the operation.</param>
        /// <returns>Populated <see cref="ARCAnalysis"/> instance.</returns>
        public ARCAnalysis VerifyARC(string rawHeaders, CancellationToken ct = default) {
            return VerifyARCAsync(rawHeaders, ct).GetAwaiter().GetResult();
        }

        /// <summary>Executes the verify arc async operation.</summary>
        public async Task<ARCAnalysis> VerifyARCAsync(string rawHeaders, CancellationToken ct = default) {
            ct.ThrowIfCancellationRequested();
            return await Task.Run(() => {
                ArcAnalysis = new ARCAnalysis();
                ArcAnalysis.Analyze(rawHeaders, _logger);
                return ArcAnalysis;
            }, ct);
        }

        private Task VerifyMessageHeaderAsync(CancellationToken cancellationToken) {
            MessageHeaderAnalysis = CheckMessageHeaders(string.Empty, cancellationToken);
            return Task.CompletedTask;
        }
    }
}
