using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace DomainDetective;

public partial class MessageHeaderAnalysis {
    /// <summary>Exchange classification fields as reported, with raw unknown values preserved.</summary>
    public Dictionary<string, string> ExchangeHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Microsoft EOP/Defender verdict tokens; these are header claims, not live policy checks.</summary>
    public Dictionary<string, string> DefenderVerdicts { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Documented token explanations with unknown values explicitly preserved.</summary>
    public Dictionary<string, string> DefenderVerdictMeanings { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Exchange mechanism code, if reported.</summary>
    public string? ExchangeAuthMechanism { get; private set; }
    /// <summary>Documented interpretation; unknown codes are never guessed.</summary>
    public string? ExchangeAuthMechanismMeaning { get; private set; }
    /// <summary>SpamAssassin score from X-Spam-Status, if parseable.</summary>
    public double? SpamAssassinScore { get; private set; }
    /// <summary>SpamAssassin tests as reported.</summary>
    public string[] SpamAssassinTests { get; private set; } = Array.Empty<string>();
    /// <summary>Rspamd symbols as reported.</summary>
    public string[] RspamdSymbols { get; private set; } = Array.Empty<string>();

    private static readonly Regex SpamScorePattern = new(@"\b(?:score|hits)\s*=\s*(?<value>-?\d+(?:\.\d+)?)", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
    private static readonly Regex SpamTestsPattern = new(@"\btests\s*=\s*(?<value>.*?)(?:\s+[a-z]+\s*=|$)", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));

    private void AnalyzeVendorMetadata() {
        ExchangeHeaders.Clear();
        DefenderVerdicts.Clear();
        DefenderVerdictMeanings.Clear();
        foreach (var field in Fields) {
            if (field.Name.StartsWith("X-MS-Exchange-", StringComparison.OrdinalIgnoreCase) || field.Name.Equals("X-OriginatorOrg", StringComparison.OrdinalIgnoreCase)
                || field.Name.Equals("X-OrganizationHeadersPreserved", StringComparison.OrdinalIgnoreCase) || field.Name.Equals("X-CrossPremisesHeadersFilteredBySendConnector", StringComparison.OrdinalIgnoreCase)) {
                if (!ExchangeHeaders.ContainsKey(field.Name)) { ExchangeHeaders[field.Name] = field.Value; }
            }
        }
        foreach (var name in new[] { "X-Forefront-Antispam-Report", "X-Microsoft-Antispam", "X-Microsoft-Antispam-Mailbox-Delivery" }) {
            var value = GetTrustedHeaderValue(name);
            if (value == null) { continue; }
            foreach (var part in MessageHeaderValueParser.Split(value)) {
                var colon = part.IndexOf(':');
                if (colon > 0) { DefenderVerdicts[part.Substring(0, colon).Trim()] = part.Substring(colon + 1).Trim(); }
            }
        }
        foreach (var verdict in DefenderVerdicts) { DefenderVerdictMeanings[verdict.Key] = MessageVendorMeanings.FilteringMeaning(verdict.Key, verdict.Value); }
        ExchangeAuthMechanism = GetTrustedHeaderValue("X-MS-Exchange-Organization-AuthMechanism");
        ExchangeAuthMechanismMeaning = ExchangeAuthMechanism == null ? null
            : int.TryParse(ExchangeAuthMechanism, out var mechanism) && mechanism == 10 ? "Externally secured connector classification (documented code 10)."
            : "Unknown mechanism; raw code preserved. No documented interpretation is asserted.";
        if (int.TryParse(ExchangeAuthMechanism, out var code) && code == 10) { AddFinding("HEADERS.Exchange.ExternallySecured", AssessmentSeverity.Warning, "AuthMechanism reports externally secured connector classification. Verify connector configuration and filtering in the tenant; headers alone do not prove policy enforcement."); }
        if (ExchangeHeaders.ContainsKey("X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp")) { AddFinding("HEADERS.Exchange.TenantAttribution", AssessmentSeverity.Warning, "The message contains original tenant-attribution connection evidence; investigate tenant/connector attribution with message trace."); }
        if (ExchangeHeaders.ContainsKey("X-CrossPremisesHeadersFilteredBySendConnector")) { AddFinding("HEADERS.Exchange.HeadersFiltered", AssessmentSeverity.Warning, "A send connector reports filtering cross-premises headers; internal classification may be affected."); }
        if (DefenderVerdicts.TryGetValue("CAT", out var category) && !string.Equals(category, "NONE", StringComparison.OrdinalIgnoreCase)) { AddFinding("HEADERS.Spam.Category", AssessmentSeverity.Warning, $"Microsoft reports category {category}; this is a receiver verdict, not independent content inspection."); }
        if (Scl >= 5) { AddFinding("HEADERS.Spam.Confidence", AssessmentSeverity.Warning, $"Microsoft reports spam confidence level {Scl}."); }
        var spam = GetHeaderValue("X-Spam-Status") ?? string.Empty;
        var score = SpamScorePattern.Match(spam);
        SpamAssassinScore = score.Success && double.TryParse(score.Groups["value"].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var number) ? number : null;
        var tests = SpamTestsPattern.Match(spam);
        SpamAssassinTests = tests.Success ? tests.Groups["value"].Value.Split(',').Select(value => value.Trim()).Where(value => value.Length > 0).ToArray() : Array.Empty<string>();
        RspamdSymbols = (GetHeaderValue("X-Rspamd-Symbols") ?? GetHeaderValue("X-Spamd-Result") ?? string.Empty).Split(new[] { ',', ';', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Select(value => value.Trim()).ToArray();
    }
}
