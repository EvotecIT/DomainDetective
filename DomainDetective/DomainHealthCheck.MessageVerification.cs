using MimeKit;
using MimeKit.Cryptography;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck {
    /// <summary>Analyzes original MIME bytes and verifies DKIM/ARC locally. DNS requires explicit opt-in.</summary>
    /// <param name="messageBytes">Original MIME message bytes, including the body.</param>
    /// <param name="options">Offline keys, explicit DNS policy, provenance, and resource limits.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Header evidence and separate cryptographic results. No message content is uploaded.</returns>
    public async Task<MessageHeaderAnalysis> AnalyzeMessageAsync(byte[] messageBytes, MessageVerificationOptions? options = null, CancellationToken cancellationToken = default) {
        if (messageBytes == null) { throw new ArgumentNullException(nameof(messageBytes)); }
        options ??= new MessageVerificationOptions();
        if (options.HeaderOptions == null || options.PublicKeyRecords == null) { throw new ArgumentException("HeaderOptions and PublicKeyRecords must not be null.", nameof(options)); }
        if (options.MaximumMessageBytes < 1 || options.MaximumDkimSignatures < 1 || options.MaximumDnsQueries < 1 || options.Timeout <= TimeSpan.Zero) {
            throw new ArgumentOutOfRangeException(nameof(options), "Verification limits must be positive.");
        }
        if (messageBytes.Length > options.MaximumMessageBytes) { throw new ArgumentException("MIME message exceeds MaximumMessageBytes.", nameof(messageBytes)); }
        cancellationToken.ThrowIfCancellationRequested();
        var boundary = MessageBodyBoundary(messageBytes);
        var headerBytes = boundary < 0 ? messageBytes.Length : boundary;
        if (options.HeaderOptions.MaximumHeaderCharacters < 1 || headerBytes > (long)options.HeaderOptions.MaximumHeaderCharacters * 4) {
            throw new ArgumentException("MIME header exceeds MaximumHeaderCharacters.", nameof(messageBytes));
        }
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(Encoding.UTF8.GetString(messageBytes, 0, headerBytes), options.HeaderOptions, _logger);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var deadline = Stopwatch.StartNew();
        timeout.CancelAfter(options.Timeout);
        using var stream = new MemoryStream(messageBytes, writable: false);
        MimeMessage message;
        try {
            message = await MimeMessage.LoadAsync(stream, timeout.Token).ConfigureAwait(false);
            // Timers have platform-dependent resolution; enforce the elapsed budget too.
            if (deadline.Elapsed >= options.Timeout) { throw new OperationCanceledException(timeout.Token); }
        } catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) {
            analysis.SignatureVerification.Add(new MessageSignatureVerification {
                Method = "DKIM / ARC", Status = MessageSignatureStatus.Inconclusive,
                Explanation = "Verification deadline reached while loading the original MIME message; signature verification was not performed."
            });
            cancellationToken.ThrowIfCancellationRequested();
            return analysis;
        } catch (FormatException) {
            // Header evidence is still useful when the full MIME parser cannot
            // produce a message suitable for cryptographic verification.
            cancellationToken.ThrowIfCancellationRequested();
            analysis.SignatureVerification.Add(new MessageSignatureVerification {
                Method = "DKIM / ARC", Status = MessageSignatureStatus.Inconclusive,
                Explanation = "Original MIME message could not be parsed; signature verification was not performed."
            });
            return analysis;
        }
        var hasBodyBoundary = boundary >= 0;
        var locator = new MessagePublicKeyLocator(options, DnsConfiguration);
        var dkim = new DkimVerifier(locator);
        var count = 0;
        foreach (var header in message.Headers.Where(header => header.Id == HeaderId.DkimSignature)) {
            var tags = MessageHeaderValueParser.ParseTags(header.Value);
            tags.TryGetValue("d", out var domain);
            tags.TryGetValue("s", out var selector);
            var result = new MessageSignatureVerification { Method = "DKIM", Domain = domain, Selector = selector };
            analysis.SignatureVerification.Add(result);
            if (!hasBodyBoundary || ++count > options.MaximumDkimSignatures) {
                result.Status = MessageSignatureStatus.NotPerformed;
                result.Explanation = !hasBodyBoundary ? "Original message body boundary is unavailable; headers alone cannot establish DKIM validity." : "Configured DKIM signature limit reached; verification is incomplete.";
                continue;
            }
            var failures = locator.Failures.Count;
            locator.BeginVerification();
            try {
                var valid = await dkim.VerifyAsync(message, header, timeout.Token).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (deadline.Elapsed >= options.Timeout) { throw new OperationCanceledException(timeout.Token); }
                result.Status = valid ? MessageSignatureStatus.Valid : MessageSignatureStatus.Invalid;
                result.Explanation = valid ? "Original message verifies using the available public key. This does not establish delivery-time DNS or sender intent." : "Signature did not validate the supplied message.";
            } catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) {
                result.Status = MessageSignatureStatus.Inconclusive;
                result.Explanation = "Verification timeout reached.";
            } catch (Exception ex) when (ex is FormatException || ex is ArgumentException || ex is InvalidOperationException || ex is NotSupportedException || ex is MimeKit.ParseException || ex is IOException) {
                result.Status = MessageSignatureStatus.Inconclusive;
                result.Explanation = "Verification could not complete: " + ex.Message;
            }
            if (locator.Failures.Count > failures) {
                result.Status = MessageSignatureStatus.Inconclusive;
                result.Explanation = string.Join(" ", locator.Failures.Skip(failures));
            }
            result.UsedDns = locator.UsedDns;
        }
        if (message.Headers.Any(header => header.Field.StartsWith("ARC-", StringComparison.OrdinalIgnoreCase))) {
            var result = new MessageSignatureVerification { Method = "ARC" };
            analysis.SignatureVerification.Add(result);
            if (!hasBodyBoundary) {
                result.Status = MessageSignatureStatus.NotPerformed;
                result.Explanation = "Original message body boundary is unavailable; full ARC verification was not performed.";
            } else {
                var failures = locator.Failures.Count;
                locator.BeginVerification();
                try {
                    var arc = await new ArcVerifier(locator).VerifyAsync(message, timeout.Token).ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    if (deadline.Elapsed >= options.Timeout) { throw new OperationCanceledException(timeout.Token); }
                    result.Status = arc.Chain == ArcSignatureValidationResult.Pass ? MessageSignatureStatus.Valid : MessageSignatureStatus.Invalid;
                    result.Explanation = "ARC cryptographic chain result: " + arc.Chain + ". A valid chain does not by itself establish trust in the sealers or their claims.";
                } catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) {
                    result.Status = MessageSignatureStatus.Inconclusive;
                    result.Explanation = "Verification timeout reached.";
                } catch (Exception ex) when (ex is FormatException || ex is ArgumentException || ex is InvalidOperationException || ex is NotSupportedException || ex is MimeKit.ParseException || ex is IOException) {
                    result.Status = MessageSignatureStatus.Inconclusive;
                    result.Explanation = "ARC verification could not complete: " + ex.Message;
                }
                if (locator.Failures.Count > failures) { result.Status = MessageSignatureStatus.Inconclusive; result.Explanation = string.Join(" ", locator.Failures.Skip(failures)); }
                result.UsedDns = locator.UsedDns;
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        return analysis;
    }

    private static int MessageBodyBoundary(byte[] bytes) {
        for (var i = 0; i < bytes.Length - 1; i++) {
            if (bytes[i] == 10 && bytes[i + 1] == 10) { return i + 2; }
            if (i + 3 < bytes.Length && bytes[i] == 13 && bytes[i + 1] == 10 && bytes[i + 2] == 13 && bytes[i + 3] == 10) { return i + 4; }
        }
        return -1;
    }
}
