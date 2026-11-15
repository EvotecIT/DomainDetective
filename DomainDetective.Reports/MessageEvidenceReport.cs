using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Views;

namespace DomainDetective.Reports;

/// <summary>Presentation-ready message evidence shared by the document, workbook and text renderers.</summary>
public sealed class MessageEvidenceReport {
    /// <summary>Reader-oriented interpretation, findings and actions.</summary>
    public MessageHeaderReportBrief Brief { get; }
    /// <summary>Plain-text evidence sections, independent of a domain assessment.</summary>
    public IReadOnlyList<MessageHeaderReport.Section> Sections { get; }
    /// <summary>Sender/recipient context, or the standalone input label.</summary>
    public string ContextLabel { get; }

    private MessageEvidenceReport(MessageHeaderReportBrief brief, IReadOnlyList<MessageHeaderReport.Section> sections, string context) {
        Brief = brief;
        Sections = sections;
        ContextLabel = context;
    }

    /// <summary>Projects an existing message analysis without acquiring or parsing evidence again.</summary>
    public static MessageEvidenceReport FromMessage(MessageHeaderAnalysis message) {
        if (message == null) { throw new ArgumentNullException(nameof(message)); }
        return new MessageEvidenceReport(MessageHeaderReportBrief.Build(message), MessageHeaderReport.Build(message),
            MessageHeaderReport.VisibleText(message.From) + " → " + MessageHeaderReport.VisibleText(message.To));
    }

    /// <summary>Recognizes message analysis and standalone ARC input; domain-labelled views remain domain assessments.</summary>
    public static MessageEvidenceReport? TryCreate(object input) {
        if (input is MessageHeaderAnalysis message) { return FromMessage(message); }
        if (input is not ArcInfo arc || DomainAssessmentBuilder.NormalizeDomain(arc.Subject) != null) { return null; }
        string Value(object? value) => value is IFormattable formatted
            ? formatted.ToString(null, CultureInfo.InvariantCulture) ?? string.Empty : value?.ToString() ?? string.Empty;
        var sections = new List<MessageHeaderReport.Section> {
            new("ARC structure", new[] { "Field", "Value" }, new[] {
                new[] { "ARC headers found", Value(arc.ArcHeadersFound) },
                new[] { "ARC-Seal count", Value(arc.SealCount) },
                new[] { "ARC-Authentication-Results count", Value(arc.AarCount) },
                new[] { "ARC-Message-Signature count", arc.Raw == null ? "Not available" : Value(arc.Raw.ArcMessageSignatureHeaders.Count) },
                new[] { "Chain state", arc.ChainState ?? "Unknown" },
                new[] { "Valid structural chain", Value(arc.ValidChain) },
                new[] { "Seals include signatures", Value(arc.SealsIncludeSignatures) },
                new[] { "Cryptographic verification", "Not performed. Header structure does not establish signature validity or sealer trust." }
            }),
            new("ARC findings", new[] { "Severity", "Code", "Message", "Where" },
                (arc.Assessments ?? Array.Empty<Assessment>()).Select(finding => new[] {
                    finding.Severity.ToString(), finding.Code ?? string.Empty, finding.Message, finding.Target ?? string.Empty
                }))
        };
        if (arc.Raw != null) {
            sections.Add(new MessageHeaderReport.Section("ARC headers", new[] { "Header", "Value" },
                arc.Raw.ArcSealHeaders.Select(value => new[] { "ARC-Seal", value })
                .Concat(arc.Raw.ArcAuthenticationResultsHeaders.Select(value => new[] { "ARC-Authentication-Results", value }))
                .Concat(arc.Raw.ArcMessageSignatureHeaders.Select(value => new[] { "ARC-Message-Signature", value }))));
            sections.Add(new MessageHeaderReport.Section("Structure issues", new[] { "Issue" },
                arc.Raw.StructureIssues.Select(value => new[] { value })));
        }
        sections.Add(new MessageHeaderReport.Section("References", new[] { "Reference" },
            (arc.References ?? Array.Empty<string>()).Select(value => new[] { value })));
        return new MessageEvidenceReport(MessageHeaderReportBrief.BuildArc(arc), sections, "ARC header evidence");
    }
}
