using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>Projects header assessments and local cryptographic outcomes into report findings.</summary>
internal static class MessageHeaderReportFindings {
    internal static IReadOnlyList<Assessment> Build(MessageHeaderAnalysis message) {
        var findings = new List<Assessment>(message.Assessments);
        foreach (var result in message.SignatureVerification.Where(result => result.Status == MessageSignatureStatus.Invalid || result.Status == MessageSignatureStatus.Inconclusive || result.Status == MessageSignatureStatus.NotPerformed)) {
            var invalid = result.Status == MessageSignatureStatus.Invalid;
            var notPerformed = result.Status == MessageSignatureStatus.NotPerformed;
            var identity = string.Join(" / ", new[] { result.Method, result.Domain, result.Selector }.Where(value => !string.IsNullOrWhiteSpace(value)));
            if (identity.Length == 0) { identity = "DKIM / ARC"; }
            findings.Add(new Assessment {
                Code = invalid ? "HEADERS.Verify.Invalid" : notPerformed ? "HEADERS.Verify.NotPerformed" : "HEADERS.Verify.Inconclusive",
                Category = "HEADERS",
                Source = "Cryptographic verification",
                Target = identity,
                Severity = invalid ? AssessmentSeverity.Error : AssessmentSeverity.Warning,
                Message = "Local " + identity + (invalid ? " cryptographic verification failed. " : notPerformed ? " cryptographic verification was not performed. " : " cryptographic verification was inconclusive. ") + result.Explanation
            });
        }
        return findings;
    }
}
