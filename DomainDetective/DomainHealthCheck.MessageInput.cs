using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck {
    /// <summary>Parses message headers offline with explicit receiver trust and expected route hosts.</summary>
    /// <param name="rawHeaders">Header text or MIME text; body content is ignored.</param>
    /// <param name="options">Trust and parsing limits.</param>
    /// <param name="expectedMxHosts">Optional expected public MX hosts.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public MessageHeaderAnalysis AnalyzeMessageHeaders(string rawHeaders, MessageHeaderAnalysisOptions? options = null, IEnumerable<string>? expectedMxHosts = null, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(rawHeaders, _logger, emitRouteDiagnostics: false, options);
        analysis.CompareExpectedMx(expectedMxHosts, _logger);
        using var collector = AssessmentCollector.ForAnalysis(_logger, analysis, category: "HEADERS");
        analysis.EmitNonMxRouteDiagnostics(_logger);
        cancellationToken.ThrowIfCancellationRequested();
        return analysis;
    }

    /// <summary>Reads a local message with bounded input and optional full-message signature verification.</summary>
    /// <param name="path">Local header or original MIME file.</param>
    /// <param name="verifySignatures">Read the full MIME message and verify DKIM/ARC; default reads only headers.</param>
    /// <param name="options">Trust, keys, explicit DNS policy, and resource limits.</param>
    /// <param name="expectedMxHosts">Optional expected public MX hosts.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<MessageHeaderAnalysis> AnalyzeMessageFileAsync(string path, bool verifySignatures = false, MessageVerificationOptions? options = null, IEnumerable<string>? expectedMxHosts = null, CancellationToken cancellationToken = default) {
        options ??= new MessageVerificationOptions();
        if (options.HeaderOptions == null || options.HeaderOptions.MaximumHeaderCharacters < 1 || options.MaximumMessageBytes < 1) { throw new ArgumentException("Input limits must be positive and HeaderOptions must be supplied.", nameof(options)); }
        var limit = verifySignatures ? options.MaximumMessageBytes : Math.Min(int.MaxValue - 1L, options.HeaderOptions.MaximumHeaderCharacters * 4L);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 8192, useAsync: true);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        var lfRun = 0;
        var complete = false;
        while (!complete) {
            var read = await stream.ReadAsync(chunk, 0, chunk.Length, cancellationToken).ConfigureAwait(false);
            if (read == 0) { break; }
            var keep = read;
            if (!verifySignatures) {
                for (var i = 0; i < read; i++) {
                    if (chunk[i] == 10) { lfRun++; }
                    else if (chunk[i] != 13) { lfRun = 0; }
                    if (lfRun == 2) { keep = i + 1; complete = true; break; }
                }
            }
            if (buffer.Length + keep > limit) { throw new ArgumentException("Message input exceeds the configured size limit.", nameof(path)); }
            buffer.Write(chunk, 0, keep);
        }
        var bytes = buffer.ToArray();
        var result = verifySignatures
            ? await AnalyzeMessageAsync(bytes, options, cancellationToken).ConfigureAwait(false)
            : AnalyzeMessageHeaders(Encoding.UTF8.GetString(bytes), options.HeaderOptions, expectedMxHosts, cancellationToken);
        if (!verifySignatures && complete) { result.HadBody = stream.Length > buffer.Length; }
        result.Source = Path.GetFullPath(path);
        if (verifySignatures) { result.CompareExpectedMx(expectedMxHosts, _logger); }
        return result;
    }
}
