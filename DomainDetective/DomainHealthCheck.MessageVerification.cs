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
        if (options.MaximumMessageBytes < 1 || options.MaximumDkimSignatures < 1 || options.MaximumDnsQueries < 1 || options.MaximumMimeComplianceIssues < 1 || options.MaximumMimeHeaderBytes < 1 || options.Timeout <= TimeSpan.Zero) {
            throw new ArgumentOutOfRangeException(nameof(options), "Verification limits must be positive.");
        }
        if (messageBytes.Length > options.MaximumMessageBytes) { throw new ArgumentException("MIME message exceeds MaximumMessageBytes.", nameof(messageBytes)); }
        cancellationToken.ThrowIfCancellationRequested();
        var boundary = MessageBodyBoundary(messageBytes);
        var headerBytes = boundary < 0 ? messageBytes.Length : boundary;
        if (options.HeaderOptions.MaximumHeaderCharacters < 1 || headerBytes > (long)options.HeaderOptions.MaximumHeaderCharacters * 4) {
            throw new ArgumentException("MIME header exceeds MaximumHeaderCharacters.", nameof(messageBytes));
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var deadline = Stopwatch.StartNew();
        timeout.CancelAfter(options.Timeout);
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(Encoding.UTF8.GetString(messageBytes, 0, headerBytes), options.HeaderOptions, _logger);
        analysis.HadBody = boundary >= 0 && boundary < messageBytes.Length;
        using var stream = new MemoryStream(messageBytes, writable: false);
        MimeMessage message;
        try {
            CryptographyModule.Initialize();
            var parserOptions = ParserOptions.Default.Clone();
            parserOptions.MaxHeaderLength = options.MaximumMimeHeaderBytes;
            var parser = new MimeParser(parserOptions, stream) { ComplianceLogger = analysis.CreateComplianceLogger(options.MaximumMimeComplianceIssues) };
            parser.ComplianceOptions.MaxIssuesPerViolation = options.MaximumMimeComplianceIssues;
            message = await parser.ParseMessageAsync(timeout.Token).ConfigureAwait(false);
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
        using var messageLifetime = message;
        var hasBodyBoundary = boundary >= 0;
        analysis.OriginalMessageInspectedForSignatures = hasBodyBoundary;
        var locator = new MessageDnsResolver(options, DnsConfiguration);
        var dkim = new DkimVerifier(locator);
        var count = 0;
        foreach (var header in message.Headers.Where(header => header.Id == HeaderId.DkimSignature)) {
            bool validTags = DkimTagList.TryParse(MessageHeaderValueParser.UnfoldRawValue(header), out var tags, out _);
            tags.TryGetValue("d", out var domain);
            tags.TryGetValue("s", out var selector);
            var result = new MessageSignatureVerification { Method = "DKIM", Domain = domain, Selector = selector };
            analysis.SignatureVerification.Add(result);
            if (!hasBodyBoundary || ++count > options.MaximumDkimSignatures) {
                result.Status = MessageSignatureStatus.NotPerformed;
                result.Explanation = !hasBodyBoundary ? "Original message body boundary is unavailable; headers alone cannot establish DKIM validity." : "Configured DKIM signature limit reached; verification is incomplete.";
                continue;
            }
            if (!validTags) {
                result.Status = MessageSignatureStatus.Invalid;
                result.Explanation = "DKIM signature tag syntax is invalid or repeats a tag.";
                continue;
            }
            var failures = locator.Failures.Count;
            locator.BeginVerification();
            try {
                var verification = await dkim.VerifyAsync(message, header, timeout.Token).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (deadline.Elapsed >= options.Timeout) { throw new OperationCanceledException(timeout.Token); }
                result.ProtocolStatus = verification.Status.ToString();
                result.FailureReason = verification.Reason;
                result.Status = verification.Status == DkimSignatureStatus.Pass ? MessageSignatureStatus.Valid :
                    verification.Status == DkimSignatureStatus.TempError ? MessageSignatureStatus.Inconclusive : MessageSignatureStatus.Invalid;
                result.Explanation = verification.Status == DkimSignatureStatus.Pass ? "Original message verifies using the available public key. This does not establish delivery-time DNS or sender intent." : "DKIM " + verification.Status + ": " + verification.Reason;
                if (verification.Status == DkimSignatureStatus.Pass) {
                    // Domain audits and message verification share the same additional
                    // key policy; keep its result separate from MimeKit's verdict.
                    ApplyMessageKeyPolicy(result, locator, header);
                }
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
        if (message.Headers.Any(header => header.Field.Equals("ARC-Seal", StringComparison.OrdinalIgnoreCase)
            || header.Field.Equals("ARC-Message-Signature", StringComparison.OrdinalIgnoreCase))) {
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
                    result.ProtocolStatus = arc.Chain.ToString();
                    result.ArcChainErrors = arc.ChainErrors.ToString();
                    var arcHeaders = (arc.Seals ?? Array.Empty<ArcHeaderValidationResult>()).AsEnumerable();
                    if (arc.MessageSignature != null) { arcHeaders = arcHeaders.Prepend(arc.MessageSignature); }
                    var inspectedHeaders = arcHeaders.ToArray();
                    result.ArcHeaders = inspectedHeaders.Select(ArcHeaderEvidence).ToArray();
                    result.FailureReason = arc.MessageSignature?.Reason ?? arc.Seals?.FirstOrDefault(seal => seal.Reason != null)?.Reason
                        ?? (arc.ChainErrors != ArcValidationErrors.None ? arc.ChainErrors.ToString() : null);
                    result.Status = arc.Chain == ArcSignatureValidationResult.Pass ? MessageSignatureStatus.Valid : MessageSignatureStatus.Invalid;
                    result.Explanation = "ARC cryptographic chain result: " + arc.Chain + ". A valid chain does not by itself establish trust in the sealers or their claims.";
                    if (arc.Chain == ArcSignatureValidationResult.Pass) {
                        foreach (var inspected in inspectedHeaders) {
                            ApplyMessageKeyPolicy(result, locator, inspected.Header);
                            if (result.Status != MessageSignatureStatus.Valid) { break; }
                        }
                    }
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

    private static void ApplyMessageKeyPolicy(MessageSignatureVerification result, MessageDnsResolver locator, Header header) {
        DkimTagList.TryParse(MessageHeaderValueParser.UnfoldRawValue(header), out var tags, out _);
        tags.TryGetValue("d", out var domain);
        tags.TryGetValue("s", out var selector);
        var records = locator.CachedRecords(DkimDnsName.Lookup(domain!, selector!));
        if (records == null || records.Count != 1) {
            // Preserve the existing evidence boundary instead of guessing which
            // of several DNS records satisfied the cryptographic verifier.
            result.Status = MessageSignatureStatus.Inconclusive;
            result.PolicyFailure = "Exactly one DKIM public-key record is required for " + DkimDnsName.Lookup(domain!, selector!) + ".";
        } else {
            try {
                tags.TryGetValue("a", out var algorithm);
                tags.TryGetValue("i", out var identity);
                // ARC i= is an instance number, not a DKIM identity.
                DkimKeyRecord.Parse(records[0]).ValidateUse(domain!, algorithm, header.Id == HeaderId.DkimSignature ? identity : null);
                return;
            } catch (DkimKeyPolicyException ex) {
                result.Status = MessageSignatureStatus.Invalid;
                result.PolicyFailure = ex.Message;
            }
        }
        result.Explanation = "DomainDetective key policy: " + result.PolicyFailure;
    }

    private static MessageArcHeaderVerification ArcHeaderEvidence(ArcHeaderValidationResult result) {
        DkimTagList.TryParse(MessageHeaderValueParser.UnfoldRawValue(result.Header), out var tags, out _);
        tags.TryGetValue("i", out var instance);
        return new MessageArcHeaderVerification {
            Header = result.Header.Field, Instance = instance, ProtocolStatus = result.Signature.ToString(), FailureReason = result.Reason
        };
    }

    private static int MessageBodyBoundary(byte[] bytes) {
        for (var i = 0; i < bytes.Length - 1; i++) {
            if (bytes[i] == 10 && bytes[i + 1] == 10) { return i + 2; }
            if (i + 3 < bytes.Length && bytes[i] == 13 && bytes[i + 1] == 10 && bytes[i + 2] == 13 && bytes[i + 3] == 10) { return i + 4; }
        }
        return -1;
    }
}
