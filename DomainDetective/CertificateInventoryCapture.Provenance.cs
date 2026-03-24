using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public sealed partial class CertificateInventoryCapture {
    private const string TargetOriginSeedApex = "seed-apex";
    private const string TargetOriginSeedExactHost = "seed-exact-host";
    private const string TargetOriginSeedWww = "seed-www";
    private const string TargetOriginCtDiscovery = "ct-discovery";
    private const string TargetOriginMxHttps = "mx-https";
    private const string TargetOriginMxMail = "mx-mail";
    private const string TargetOriginAdditionalEndpoint = "additional-endpoint";

    private const string CaptureDispositionLiveProbe = "live-probe";
    private const string CaptureDispositionReusedRecentSuccess = "reused-recent-success";
    private const string CaptureDispositionReusedRecentStableFailure = "reused-recent-stable-failure";

    private static bool AddHttpsTarget(
        HashSet<string> httpsTargets,
        Dictionary<string, HashSet<string>> originsByEndpointKey,
        string target,
        params string[] origins) {
        if (string.IsNullOrWhiteSpace(target)) {
            return false;
        }

        string normalizedTarget = target.Trim();
        bool added = httpsTargets.Add(normalizedTarget);
        string endpointKey = TryBuildHttpsEndpointKey(normalizedTarget, out string key)
            ? key
            : normalizedTarget;
        MergeTargetOrigins(originsByEndpointKey, endpointKey, origins);
        return added;
    }

    private static IReadOnlyList<string> GetTrackedOrigins(
        IReadOnlyDictionary<string, HashSet<string>> originsByEndpointKey,
        string endpointKey) {
        if (string.IsNullOrWhiteSpace(endpointKey) ||
            originsByEndpointKey == null ||
            !originsByEndpointKey.TryGetValue(endpointKey, out HashSet<string>? origins) ||
            origins == null ||
            origins.Count == 0) {
            return Array.Empty<string>();
        }

        return origins
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static IReadOnlyList<string> GetTrackedOrigins(
        IReadOnlyDictionary<string, HashSet<string>> originsByEndpointKey,
        CertificateInventoryEntry entry) {
        if (entry == null) {
            return Array.Empty<string>();
        }

        string endpointKey = BuildInventoryEntryEndpointKey(entry);
        return GetTrackedOrigins(originsByEndpointKey, endpointKey);
    }

    private static void ApplyEntryProvenance(
        CertificateInventoryEntry entry,
        IReadOnlyList<string> targetOrigins,
        string captureDisposition) {
        if (entry == null) {
            return;
        }

        entry.TargetOrigins = MergeDistinctStrings(entry.TargetOrigins, targetOrigins);
        entry.CaptureDisposition = string.IsNullOrWhiteSpace(captureDisposition)
            ? string.Empty
            : captureDisposition.Trim();
    }

    private static void MergeTargetOrigins(
        Dictionary<string, HashSet<string>> originsByEndpointKey,
        string endpointKey,
        IEnumerable<string>? origins) {
        if (originsByEndpointKey == null || string.IsNullOrWhiteSpace(endpointKey) || origins == null) {
            return;
        }

        if (!originsByEndpointKey.TryGetValue(endpointKey, out HashSet<string>? trackedOrigins)) {
            trackedOrigins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            originsByEndpointKey[endpointKey] = trackedOrigins;
        }

        foreach (string origin in origins) {
            if (!string.IsNullOrWhiteSpace(origin)) {
                trackedOrigins.Add(origin.Trim());
            }
        }
    }

    private static void PruneTrackedHttpsOrigins(
        Dictionary<string, HashSet<string>> originsByEndpointKey,
        IEnumerable<string> keptHttpsTargets) {
        if (originsByEndpointKey == null || originsByEndpointKey.Count == 0) {
            return;
        }

        var keptKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string target in keptHttpsTargets ?? Array.Empty<string>()) {
            if (TryBuildHttpsEndpointKey(target, out string endpointKey)) {
                keptKeys.Add(endpointKey);
            }
        }

        foreach (string endpointKey in originsByEndpointKey.Keys.ToList()) {
            if (!keptKeys.Contains(endpointKey)) {
                originsByEndpointKey.Remove(endpointKey);
            }
        }
    }

    private static string BuildInventoryEntryEndpointKey(CertificateInventoryEntry entry) {
        string host = !string.IsNullOrWhiteSpace(entry.ResolvedHost)
            ? entry.ResolvedHost!
            : entry.Host;
        return BuildEndpointKey(host, entry.Port, entry.Service);
    }

    private static IReadOnlyDictionary<string, int> BuildTargetOriginCounts(IEnumerable<CertificateInventoryEntry> entries) {
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (entries == null) {
            return counts;
        }

        foreach (CertificateInventoryEntry entry in entries) {
            if (entry?.TargetOrigins == null) {
                continue;
            }

            foreach (string origin in entry.TargetOrigins) {
                if (string.IsNullOrWhiteSpace(origin)) {
                    continue;
                }

                string normalizedOrigin = origin.Trim();
                counts.TryGetValue(normalizedOrigin, out int current);
                counts[normalizedOrigin] = current + 1;
            }
        }

        return counts
            .OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(static pair => pair.Key, static pair => pair.Value, StringComparer.OrdinalIgnoreCase);
    }

    private static IReadOnlyDictionary<string, int> BuildCaptureDispositionCounts(IEnumerable<CertificateInventoryEntry> entries) {
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (entries == null) {
            return counts;
        }

        foreach (CertificateInventoryEntry entry in entries) {
            if (entry == null || string.IsNullOrWhiteSpace(entry.CaptureDisposition)) {
                continue;
            }

            string disposition = entry.CaptureDisposition.Trim();
            counts.TryGetValue(disposition, out int current);
            counts[disposition] = current + 1;
        }

        return counts
            .OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(static pair => pair.Key, static pair => pair.Value, StringComparer.OrdinalIgnoreCase);
    }

    private static TargetDecisionDiagnosticEntry CloneTargetDecisionDiagnosticEntry(TargetDecisionDiagnosticEntry diagnostic) {
        if (diagnostic == null) {
            return new TargetDecisionDiagnosticEntry();
        }

        string stage = diagnostic.Stage ?? string.Empty;
        string action = diagnostic.Action ?? string.Empty;
        string reason = diagnostic.Reason ?? string.Empty;

        return new TargetDecisionDiagnosticEntry {
            Stage = stage,
            Action = action,
            Reason = reason,
            Severity = ResolveTargetDecisionSeverity(stage, action, reason, diagnostic.Severity),
            RecommendedAction = ResolveTargetDecisionRecommendedAction(stage, action, reason, diagnostic.RecommendedAction),
            Target = diagnostic.Target ?? string.Empty,
            Service = diagnostic.Service,
            PriorityScore = diagnostic.PriorityScore,
            Message = diagnostic.Message,
            TargetOrigins = diagnostic.TargetOrigins == null
                ? Array.Empty<string>()
                : diagnostic.TargetOrigins
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Select(static value => value.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
                    .ToList()
        };
    }

    private static IReadOnlyList<TargetDecisionSummaryEntry> BuildTargetDecisionSummary(
        IEnumerable<TargetDecisionDiagnosticEntry> diagnostics,
        int maxExamples = 3) {
        if (diagnostics == null) {
            return Array.Empty<TargetDecisionSummaryEntry>();
        }

        int effectiveMaxExamples = Math.Max(1, maxExamples);
        return diagnostics
            .Where(static diagnostic => diagnostic != null)
            .GroupBy(
                static diagnostic => new {
                    Stage = (diagnostic.Stage ?? string.Empty).Trim(),
                    Action = (diagnostic.Action ?? string.Empty).Trim(),
                    Reason = (diagnostic.Reason ?? string.Empty).Trim()
                })
            .Select(group => {
                string severity = ResolveTargetDecisionSeverity(group.Key.Stage, group.Key.Action, group.Key.Reason, group.Select(static diagnostic => diagnostic.Severity).FirstOrDefault());
                string recommendedAction = ResolveTargetDecisionRecommendedAction(group.Key.Stage, group.Key.Action, group.Key.Reason, group.Select(static diagnostic => diagnostic.RecommendedAction).FirstOrDefault());
                return new TargetDecisionSummaryEntry {
                    Stage = group.Key.Stage,
                    Action = group.Key.Action,
                    Reason = group.Key.Reason,
                    Severity = severity,
                    RecommendedAction = recommendedAction,
                    Count = group.Count(),
                    ExampleTargets = group
                        .Select(static diagnostic => diagnostic.Target)
                        .Where(static target => !string.IsNullOrWhiteSpace(target))
                        .Select(static target => target.Trim())
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .OrderBy(static target => target, StringComparer.OrdinalIgnoreCase)
                        .Take(effectiveMaxExamples)
                        .ToList(),
                    ExampleServices = group
                        .Select(static diagnostic => diagnostic.Service)
                        .Where(static service => !string.IsNullOrWhiteSpace(service))
                        .Select(static service => service!.Trim())
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .OrderBy(static service => service, StringComparer.OrdinalIgnoreCase)
                        .Take(effectiveMaxExamples)
                        .ToList(),
                    TargetOrigins = group
                        .SelectMany(static diagnostic => diagnostic.TargetOrigins ?? Array.Empty<string>())
                        .Where(static origin => !string.IsNullOrWhiteSpace(origin))
                        .Select(static origin => origin.Trim())
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .OrderBy(static origin => origin, StringComparer.OrdinalIgnoreCase)
                        .ToList()
                };
            })
            .OrderByDescending(static summary => summary.Count)
            .ThenBy(static summary => summary.Stage, StringComparer.OrdinalIgnoreCase)
            .ThenBy(static summary => summary.Action, StringComparer.OrdinalIgnoreCase)
            .ThenBy(static summary => summary.Reason, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static TargetDecisionSummaryEntry CloneTargetDecisionSummaryEntry(TargetDecisionSummaryEntry summary) {
        if (summary == null) {
            return new TargetDecisionSummaryEntry();
        }

        return new TargetDecisionSummaryEntry {
            Stage = summary.Stage ?? string.Empty,
            Action = summary.Action ?? string.Empty,
            Reason = summary.Reason ?? string.Empty,
            Severity = ResolveTargetDecisionSeverity(summary.Stage, summary.Action, summary.Reason, summary.Severity),
            RecommendedAction = ResolveTargetDecisionRecommendedAction(summary.Stage, summary.Action, summary.Reason, summary.RecommendedAction),
            Count = summary.Count,
            ExampleTargets = summary.ExampleTargets == null
                ? Array.Empty<string>()
                : summary.ExampleTargets
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Select(static value => value.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
                    .ToList(),
            ExampleServices = summary.ExampleServices == null
                ? Array.Empty<string>()
                : summary.ExampleServices
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Select(static value => value.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
                    .ToList(),
            TargetOrigins = summary.TargetOrigins == null
                ? Array.Empty<string>()
                : summary.TargetOrigins
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Select(static value => value.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
                    .ToList()
        };
    }

    private static string ResolveTargetDecisionSeverity(
        string? stage,
        string? action,
        string? reason,
        string? currentSeverity) {
        if (!string.IsNullOrWhiteSpace(currentSeverity)) {
            return currentSeverity!.Trim();
        }

        string normalizedStage = (stage ?? string.Empty).Trim();
        string normalizedAction = (action ?? string.Empty).Trim();
        string normalizedReason = (reason ?? string.Empty).Trim();

        if (normalizedStage.Equals("additional-endpoints", StringComparison.OrdinalIgnoreCase) &&
            normalizedAction.Equals("rejected", StringComparison.OrdinalIgnoreCase)) {
            return "warning";
        }

        if (normalizedStage.Equals("target-limit", StringComparison.OrdinalIgnoreCase) &&
            normalizedReason.Equals("max-targets", StringComparison.OrdinalIgnoreCase)) {
            return "informational";
        }

        return "informational";
    }

    private static string ResolveTargetDecisionRecommendedAction(
        string? stage,
        string? action,
        string? reason,
        string? currentRecommendedAction) {
        if (!string.IsNullOrWhiteSpace(currentRecommendedAction)) {
            return currentRecommendedAction!.Trim();
        }

        string normalizedStage = (stage ?? string.Empty).Trim();
        string normalizedAction = (action ?? string.Empty).Trim();
        string normalizedReason = (reason ?? string.Empty).Trim();

        if (normalizedStage.Equals("additional-endpoints", StringComparison.OrdinalIgnoreCase) &&
            normalizedAction.Equals("rejected", StringComparison.OrdinalIgnoreCase) &&
            normalizedReason.Equals("invalid-endpoint", StringComparison.OrdinalIgnoreCase)) {
            return "Fix or remove the malformed additional endpoint value.";
        }

        if (normalizedStage.Equals("additional-endpoints", StringComparison.OrdinalIgnoreCase) &&
            normalizedAction.Equals("rejected", StringComparison.OrdinalIgnoreCase) &&
            normalizedReason.Equals("unsupported-scheme", StringComparison.OrdinalIgnoreCase)) {
            return "Use a supported HTTPS or mail endpoint scheme.";
        }

        if (normalizedStage.Equals("target-limit", StringComparison.OrdinalIgnoreCase) &&
            normalizedReason.Equals("max-targets", StringComparison.OrdinalIgnoreCase)) {
            return "Increase MaxTargets or narrow discovery scope if the omitted targets should be probed.";
        }

        return "Review the decision details if the dropped or rejected target was expected.";
    }
}
