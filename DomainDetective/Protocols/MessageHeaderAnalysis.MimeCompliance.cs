using MimeKit;
using System.Collections.Generic;

namespace DomainDetective;

public partial class MessageHeaderAnalysis {
    private readonly List<MimeComplianceIssue> mimeComplianceIssues = new();
    /// <summary>MIME parser diagnostics, including whether a position identifies a byte, line or element.</summary>
    public IReadOnlyList<MimeComplianceIssue> MimeComplianceIssues => mimeComplianceIssues;
    /// <summary>Whether additional MIME diagnostics were omitted at the configured total limit.</summary>
    public bool MimeComplianceTruncated { get; internal set; }

    private sealed class ComplianceLogger(MessageHeaderAnalysis analysis, int maximum) : IMimeComplianceLogger {
        public void Log(in MimeComplianceIssue issue) {
            if (analysis.mimeComplianceIssues.Count >= maximum) {
                if (!analysis.MimeComplianceTruncated) {
                    analysis.MimeComplianceTruncated = true;
                    analysis.AddFinding("MIME.Compliance.Truncated", AssessmentSeverity.Info, "Additional MIME diagnostics were omitted at the configured limit.");
                }
                return;
            }
            analysis.mimeComplianceIssues.Add(issue);
            var severity = issue.Severity == MimeComplianceSeverity.Critical ? AssessmentSeverity.Error :
                issue.Severity == MimeComplianceSeverity.Major ? AssessmentSeverity.Warning : AssessmentSeverity.Info;
            analysis.AddFinding("MIME." + issue.Violation, severity,
                $"MIME {issue.Violation} at line {issue.LineNumber}, column {issue.ColumnNumber} ({issue.PositionKind}).");
        }
    }

    internal IMimeComplianceLogger CreateComplianceLogger(int maximum) => new ComplianceLogger(this, maximum);
}
