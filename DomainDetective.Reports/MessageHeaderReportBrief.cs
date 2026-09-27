using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>Reader-oriented interpretation shared by message report formats.</summary>
public sealed class MessageHeaderReportBrief {
    /// <summary>Readable subject label; the full subject remains in the evidence appendix.</summary>
    public string SubjectLabel { get; private set; } = string.Empty;
    /// <summary>Short conclusion limited to the supplied evidence.</summary>
    public string Summary { get; private set; } = string.Empty;
    /// <summary>What the analysis establishes, and what remains unknown.</summary>
    public IReadOnlyList<string> Evidence { get; private set; } = Array.Empty<string>();
    /// <summary>Prioritized problems, with informational observations kept in the evidence appendix.</summary>
    public IReadOnlyList<Assessment> Findings { get; private set; } = Array.Empty<Assessment>();
    /// <summary>Existing catalog advice for actionable assessments.</summary>
    public IReadOnlyList<RecommendationAdvice> Actions { get; private set; } = Array.Empty<RecommendationAdvice>();

    /// <summary>Interprets observed results without equating receiver claims with cryptographic proof.</summary>
    public static MessageHeaderReportBrief Build(MessageHeaderAnalysis message) {
        if (message == null) { throw new ArgumentNullException(nameof(message)); }
        var findings = message.Assessments.Where(a => a.Severity != AssessmentSeverity.Info).OrderByDescending(a => a.Severity).ToArray();
        var errors = findings.Count(a => a.Severity == AssessmentSeverity.Error);
        var warnings = findings.Length - errors;
        var evidence = new List<string>();
        if (message.SignatureVerification.Count == 0) {
            evidence.Add("Cryptographic verification was not performed. Reported DKIM or ARC passes are receiver claims, not proof of the original message's validity.");
        } else {
            foreach (var result in message.SignatureVerification) {
                evidence.Add($"{result.Method} cryptographic verification: {result.Status}. {result.Explanation}");
            }
        }
        evidence.Add(string.IsNullOrWhiteSpace(message.AuthServId)
            ? "No usable receiver authentication result was selected. Sender authentication remains unknown from this evidence."
            : $"Selected receiver: {message.AuthServId}; provenance: {message.AuthenticationTrust}. Reported SPF: {message.SpfResult ?? "unknown"}; DKIM: {message.DkimResult ?? "unknown"}; DMARC: {message.DmarcResult ?? "unknown"}.");
        evidence.Add($"Reported route contains {message.ReceivedHops.Count} hop(s). " +
            (message.TotalTransitTime.HasValue ? $"Reported transit time: {message.TotalTransitTime}. " : "Transit time cannot be established. ") +
            (message.HasClockSkew ? "Clock skew limits interpretation of delays. " : string.Empty) +
            "Route and TLS declarations are header evidence; they are not an independent connection measurement.");
        evidence.Add($"Identity alignment: SPF {message.SpfAlignment ?? "unknown"}; reported DKIM {message.DkimAlignment ?? "unknown"}. Alignment and cryptographic verification answer different questions.");
        var invalid = message.SignatureVerification.Count(result => result.Status == MessageSignatureStatus.Invalid);
        var inconclusive = message.SignatureVerification.Count(result => result.Status == MessageSignatureStatus.Inconclusive);
        var verificationSummary = invalid > 0 ? $"Cryptographic verification failed for {invalid} signature or chain result(s). "
            : inconclusive > 0 ? $"Cryptographic verification could not reach a conclusion for {inconclusive} result(s). " : string.Empty;
        var actions = RecommendationEngine.FromProblems(findings).ToList();
        if (invalid > 0 || inconclusive > 0) {
            actions.Insert(0, new RecommendationAdvice {
                Title = "Investigate signature verification results",
                Why = "An invalid or inconclusive result cannot establish cryptographic validity of this message.",
                How = "Preserve the original MIME bytes, review each verification explanation and key source, and compare with receiver authentication evidence.",
                Verify = "Repeat verification against the preserved original message and the correct public key; keep receiver claims and local verification separate."
            });
        }
        var subject = MessageHeaderReport.VisibleText(message.Subject);
        if (subject.Length > 160) {
            var length = char.IsHighSurrogate(subject[159]) ? 159 : 160;
            subject = subject.Substring(0, length) + "… (full subject in evidence)";
        }
        return new MessageHeaderReportBrief {
            SubjectLabel = subject,
            Summary = verificationSummary + (findings.Length == 0
                ? "No warning or error assessments were raised for the supplied evidence. This does not establish that the sender or message is safe."
                : $"Review {errors} error(s) and {warnings} warning(s) before relying on the authentication or delivery evidence."),
            Evidence = evidence.Select(MessageHeaderReport.VisibleText).ToArray(),
            Findings = findings,
            Actions = actions
        };
    }
}
