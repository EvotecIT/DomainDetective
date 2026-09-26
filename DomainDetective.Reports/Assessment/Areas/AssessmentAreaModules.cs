using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>
/// Curated reading of one check area: the key numbers, facts and evidence that matter for that check, built from its
/// typed view instead of the generic property listing. The HTML report shows them per domain, and the assessment JSON
/// carries them to other consumers such as DomainDetectiveNext.
/// </summary>
internal interface IAssessmentAreaModule {
    /// <summary>Checks this module reads.</summary>
    IReadOnlyList<HealthCheckType> Checks { get; }

    /// <summary>
    /// Fills <see cref="CheckAssessment.Metrics"/>, <see cref="CheckAssessment.Facts"/> and
    /// <see cref="CheckAssessment.Evidence"/> from the check's views. Returns false when none of the views is one the
    /// module understands, so the generic reading is kept.
    /// </summary>
    bool Describe(CheckAssessment check, int maxRows);
}

/// <summary>Registry of <see cref="IAssessmentAreaModule"/> implementations.</summary>
internal static class AssessmentAreaModules {
    private static readonly Dictionary<HealthCheckType, IAssessmentAreaModule> Modules = Build(
        new SpfAreaModule(),
        new DmarcAreaModule(),
        new DkimAreaModule(),
        new MxAreaModule(),
        new MailTlsAreaModule(),
        new MtaStsAreaModule(),
        new TlsRptAreaModule(),
        new BimiAreaModule());

    /// <summary>Module for a check, or null when the check uses the generic reading.</summary>
    internal static IAssessmentAreaModule? For(HealthCheckType? check)
        => check.HasValue && Modules.TryGetValue(check.Value, out IAssessmentAreaModule? module) ? module : null;

    private static Dictionary<HealthCheckType, IAssessmentAreaModule> Build(params IAssessmentAreaModule[] modules) {
        var map = new Dictionary<HealthCheckType, IAssessmentAreaModule>();
        foreach (IAssessmentAreaModule module in modules) {
            foreach (HealthCheckType check in module.Checks) map.Add(check, module);
        }
        return map;
    }
}

/// <summary>Small builders shared by the area modules.</summary>
internal static class AreaText {
    internal static CheckMetric Metric(string label, string value, MetricState state = MetricState.Neutral, string? note = null)
        => new() { Label = label, Value = value, State = state, Note = note };

    internal static void Fact(CheckAssessment check, string label, string? value) {
        if (!string.IsNullOrWhiteSpace(value)) check.Facts.Add(new CheckFact { Label = label, Value = value!.Trim() });
    }

    internal static void Code(CheckAssessment check, string title, string? text) {
        if (!string.IsNullOrWhiteSpace(text)) check.Evidence.Add(new CheckEvidence { Title = title, Kind = CheckEvidenceKind.Code, Text = text!.Trim() });
    }

    internal static void List(CheckAssessment check, string title, IEnumerable<string?> items, int maxRows) {
        List<string> values = items.Where(static i => !string.IsNullOrWhiteSpace(i)).Select(static i => i!.Trim()).ToList();
        if (values.Count == 0) return;
        var evidence = new CheckEvidence { Title = title, Kind = CheckEvidenceKind.List, Omitted = Math.Max(0, values.Count - maxRows) };
        evidence.Items.AddRange(values.Take(maxRows));
        check.Evidence.Add(evidence);
    }

    internal static void Table(CheckAssessment check, string title, IReadOnlyList<string> columns, IEnumerable<IReadOnlyList<string?>> rows, int maxRows) {
        List<IReadOnlyList<string?>> all = rows.ToList();
        if (all.Count == 0) return;
        var evidence = new CheckEvidence { Title = title, Kind = CheckEvidenceKind.Table, Omitted = Math.Max(0, all.Count - maxRows) };
        evidence.Columns.AddRange(columns);
        foreach (IReadOnlyList<string?> row in all.Take(maxRows)) evidence.Rows.Add(row.Select(static c => c ?? string.Empty).ToList());
        check.Evidence.Add(evidence);
    }

    internal static string N(int value) => value.ToString("N0", CultureInfo.InvariantCulture);

    internal static string YesNo(bool value) => value ? "Yes" : "No";

    internal static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value!.Trim();

    /// <summary>Domain of a report address such as <c>mailto:dmarc@example.com!10m</c> or an HTTPS URL.</summary>
    internal static string? AddressDomain(string address) {
        string value = address.Trim();
        int bang = value.IndexOf('!');
        if (bang > 0) value = value.Substring(0, bang);
        if (value.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) value = value.Substring(7);
        int at = value.LastIndexOf('@');
        if (at >= 0) return value.Substring(at + 1).TrimEnd('.').ToLowerInvariant();
        return Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) ? uri.Host.ToLowerInvariant() : null;
    }

    /// <summary>True when <paramref name="host"/> is <paramref name="domain"/> or one of its subdomains.</summary>
    internal static bool SameOrganization(string? host, string domain)
        => host != null && (host.Equals(domain, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase));
}
