using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace DomainDetective.Reports;

/// <summary>Format-independent message evidence projection shared by report writers.</summary>
public static class MessageHeaderReport {
    /// <summary>A report section whose cells are plain text.</summary>
    public sealed class Section {
        /// <summary>Section title.</summary>
        public string Title { get; }
        /// <summary>Column labels.</summary>
        public IReadOnlyList<string> Columns { get; }
        /// <summary>Plain-text rows, including visible direction-control code points.</summary>
        public IReadOnlyList<IReadOnlyList<string>> Rows { get; }
        internal Section(string title, string[] columns, IEnumerable<string[]> rows) {
            Title = title;
            Columns = columns;
            Rows = rows.Select(row => (IReadOnlyList<string>)row.Select(VisibleText).ToArray()).ToArray();
        }
    }

    /// <summary>Builds message evidence sections without executing links or treating header claims as verification.</summary>
    public static IReadOnlyList<Section> Build(MessageHeaderAnalysis message) {
        if (message == null) { throw new ArgumentNullException(nameof(message)); }
        string Value(object? value) => value is IFormattable formatted ? formatted.ToString(null, CultureInfo.InvariantCulture) ?? string.Empty : value?.ToString() ?? string.Empty;
        var sections = new List<Section> {
            new("Message", new[] { "Field", "Value" }, new[] {
                new[] { "Source", Value(message.Source) }, new[] { "Body supplied", Value(message.HadBody) },
                new[] { "Subject", Value(message.Subject) }, new[] { "From", Value(message.From) }, new[] { "To", Value(message.To) },
                new[] { "Reply-To addresses", string.Join("; ", message.ReplyToAddresses.Select(value => value.Address)) },
                new[] { "Return-Path addresses", string.Join("; ", message.ReturnPathAddresses.Select(value => value.Address)) },
                new[] { "Date", Value(message.Date) }, new[] { "Selected authserv-id", Value(message.AuthServId) },
                new[] { "Authentication provenance", Value(message.AuthenticationTrust) }, new[] { "SPF identity alignment", Value(message.SpfAlignment) },
                new[] { "DKIM reported identity alignment", Value(message.DkimAlignment) }, new[] { "Total reported transit", Value(message.TotalTransitTime) },
                new[] { "Clock skew", Value(message.HasClockSkew) }, new[] { "Omitted hops", Value(message.OmittedReceivedHops) },
                new[] { "Composite authentication", Value(message.CompAuthResult) }, new[] { "Composite reason", Value(message.CompAuthReason) }, new[] { "Composite reason meaning", Value(message.CompAuthReasonMeaning) }
            }),
            new("Cryptographic verification", new[] { "Method", "Domain", "Selector", "Outcome", "DNS used", "Explanation" },
                message.SignatureVerification.Count == 0 ? new[] { new[] { "DKIM / ARC", "", "", "Not performed", "False", "Header analysis does not establish cryptographic validity. Supply an original MIME message for verification." } }
                : message.SignatureVerification.Select(value => new[] { value.Method, Value(value.Domain), Value(value.Selector), Value(value.Status), Value(value.UsedDns), value.Explanation })),
            new("Receiver-reported authentication", new[] { "Field", "Writer", "Provenance", "Method", "Result", "Properties" },
                message.AuthenticationResults.SelectMany(value => value.Methods.Select(method => new[] { value.HeaderName, Value(value.AuthServId), Value(value.Trust), method.Method, method.Result, string.Join("; ", method.Properties.Select(pair => pair.Key + "=" + pair.Value)) }))),
            new("Received path (delivery order)", new[] { "Header index", "From", "IP", "By", "Protocol", "TLS", "Cipher", "Reported time", "Delay", "HELO", "Reported reverse DNS", "Private IP", "Provider hints" },
                message.ReceivedHops.Select(value => new[] { Value(value.HeaderIndex), Value(value.FromHost), Value(value.FromIp), Value(value.ByHost), Value(value.ProtocolClass ?? value.With), Value(value.TlsVersion), Value(value.TlsCipher), Value(value.Timestamp), Value(value.HopDelay), Value(value.Helo), Value(value.ReportedReverseDns), Value(value.IsPrivateIp), string.Join(", ", value.ProviderHints) })),
            new("DKIM signature metadata", new[] { "Domain", "Selector", "Algorithm", "Canonicalization", "Signed headers", "Body length", "Expiry", "Receiver result" },
                message.DkimSignatures.Select(value => new[] { Value(value.Domain), Value(value.Selector), Value(value.Algorithm), Value(value.Canonicalization), string.Join(":", value.SignedHeaders), Value(value.BodyLength), Value(value.Expires), Value(value.ReceiverResult) })),
            new("ARC structure", new[] { "Field", "Value" }, new[] {
                new[] { "Structure", Value(message.ArcStructure.ChainState) }, new[] { "Declared chain failure", Value(message.ArcStructure.ChainValidationFailed) },
                new[] { "Structure issues", string.Join(" ", message.ArcStructure.StructureIssues) }, new[] { "Evidence boundary", "Complete header structure is separate from cryptographic validity and sealer trust." }
            }),
            new("ARC instances (reported)", new[] { "Instance", "Sealer", "Prior-chain token", "Writer", "Authentication claims" },
                message.ArcStructure.Instances.Select(value => new[] { Value(value.Instance), Value(value.SealerDomain), Value(value.ChainValidation), Value(value.Authentication?.AuthServId),
                    string.Join("; ", value.Authentication?.Methods.Select(method => method.Method + "=" + method.Result + " " + string.Join(" ", method.Properties.Select(pair => pair.Key + "=" + pair.Value))) ?? Array.Empty<string>()) })),
            new("Exchange classification (reported)", new[] { "Field", "Value" }, message.ExchangeHeaders.Select(pair => new[] { pair.Key, pair.Value })),
            new("Microsoft filtering (reported)", new[] { "Token", "Value", "Meaning" }, message.DefenderVerdicts.Select(pair => new[] { pair.Key, pair.Value, message.DefenderVerdictMeanings.TryGetValue(pair.Key, out var meaning) ? meaning : string.Empty })),
            new("Spam and mailing list", new[] { "Field", "Value" }, new[] {
                new[] { "SpamAssassin score", Value(message.SpamAssassinScore) }, new[] { "SpamAssassin tests", string.Join(", ", message.SpamAssassinTests) },
                new[] { "Rspamd symbols", string.Join(", ", message.RspamdSymbols) }, new[] { "List-Id", Value(message.ListId) },
                new[] { "List-Unsubscribe", Value(message.ListUnsubscribe) }, new[] { "One-click advertised", Value(message.ListUnsubscribeOneClick) }
            }),
            new("Findings", new[] { "Severity", "Code", "Message" }, message.Assessments.Select(value => new[] { Value(value.Severity), Value(value.Code), Value(value.Message) })),
            new("All header fields", new[] { "Field", "Value" }, message.Fields.Select(value => new[] { value.Name, value.Value }))
        };
        return sections;
    }

    /// <summary>Makes Unicode direction controls and line breaks visible in report cells.</summary>
    public static string VisibleText(string? value) {
        var text = new StringBuilder();
        foreach (var ch in value ?? string.Empty) {
            if (ch == '\u061c' || ch == '\u200e' || ch == '\u200f' || (ch >= '\u202a' && ch <= '\u202e') || (ch >= '\u2066' && ch <= '\u2069')) { text.Append("[U+").Append(((int)ch).ToString("X4", CultureInfo.InvariantCulture)).Append(']'); }
            else if (ch == '\r' || ch == '\n' || ch == '\t') { text.Append(' '); }
            else if (!char.IsControl(ch)) { text.Append(ch); }
        }
        return text.ToString();
    }

    /// <summary>Produces an offline plain-text report suitable for console output.</summary>
    public static string ToText(MessageHeaderAnalysis message) {
        var output = new StringBuilder();
        foreach (var section in Build(message).Where(section => section.Rows.Count > 0)) {
            output.AppendLine(section.Title);
            foreach (var row in section.Rows) { output.AppendLine(string.Join(" | ", row)); }
            output.AppendLine();
        }
        return output.ToString();
    }
}
