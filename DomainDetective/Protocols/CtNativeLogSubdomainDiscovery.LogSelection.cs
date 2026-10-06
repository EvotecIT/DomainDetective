using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

internal sealed partial class NativeCtLogSubdomainDiscovery {
    private async Task<IReadOnlyList<ResolvedCtLogDescriptor>> ResolveLogUrlsAsync(
        NativeCtLogSubdomainDiscoveryOptions options,
        CancellationToken cancellationToken,
        bool applyCap) {
        var descriptors = new Dictionary<string, ResolvedCtLogDescriptor>(StringComparer.OrdinalIgnoreCase);
        var sourceOrder = 0;
        if (options.ExplicitLogUrls != null && options.ExplicitLogUrls.Count > 0) {
            foreach (var raw in options.ExplicitLogUrls) {
                var normalized = NormalizeLogUrl(raw);
                if (normalized != null) {
                    AddResolvedLogDescriptor(descriptors, normalized, null, null, isRetired: false, sourceOrder++);
                }
            }
            IReadOnlyList<ResolvedCtLogDescriptor> explicitDescriptors = ApplyLogSelectionPolicy(descriptors.Values.ToList(), options);
            return applyCap
                ? ApplyLogCap(explicitDescriptors, options.MaxLogsToProcess, options.PrioritizeLatestExactMatch)
                : BuildExtendedProcessingOrder(explicitDescriptors, options.MaxLogsToProcess, options.PrioritizeLatestExactMatch);
        }

        if (string.IsNullOrWhiteSpace(options.LogListUrl)) {
            return Array.Empty<ResolvedCtLogDescriptor>();
        }

        var logListUrls = new List<string> { options.LogListUrl };
        if (options.IncludeRetiredLogs &&
            !string.Equals(options.LogListUrl, HistoricalAllLogsListUrl, StringComparison.OrdinalIgnoreCase)) {
            logListUrls.Add(HistoricalAllLogsListUrl);
        }

        foreach (var logListUrl in logListUrls) {
            sourceOrder = await PopulateDescriptorsFromLogListAsync(
                logListUrl,
                options,
                descriptors,
                cancellationToken,
                sourceOrder).ConfigureAwait(false);
        }

        var resolvedDescriptors = descriptors.Values.ToList();
        var eligibleDescriptors = ApplyLogSelectionPolicy(
            FilterLogsForCurrentQuery(resolvedDescriptors, DateTimeOffset.UtcNow),
            options);
        return applyCap
            ? ApplyLogCap(eligibleDescriptors, options.MaxLogsToProcess, options.PrioritizeLatestExactMatch)
            : BuildExtendedProcessingOrder(eligibleDescriptors, options.MaxLogsToProcess, options.PrioritizeLatestExactMatch);
    }

    private static bool HasConsumedLogBudget(int maxLogsToProcess, int consumedLogBudget) {
        return maxLogsToProcess > 0 && consumedLogBudget >= maxLogsToProcess;
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> PrioritizeLogDescriptorsByHealth(
        IReadOnlyList<ResolvedCtLogDescriptor> logDescriptors,
        NativeCtCursorState cursor,
        NativeCtLogSubdomainDiscoveryOptions options,
        DateTimeOffset observedUtc) {
        if (logDescriptors == null || logDescriptors.Count <= 1 || cursor == null || options == null || options.MaxLogsToProcess <= 0) {
            return logDescriptors ?? Array.Empty<ResolvedCtLogDescriptor>();
        }

        var preferredPrefixes = NormalizeLogUrlPrefixes(options.PreferredLogUrlPrefixes);
        int selectedCount = Math.Min(options.MaxLogsToProcess, logDescriptors.Count);
        return logDescriptors
            .Select((descriptor, index) => new {
                Descriptor = descriptor,
                Index = index,
                SelectedBoost = index < selectedCount ? 0 : 1,
                HealthPriority = ClassifyLogHealthPriority(cursor, descriptor.Url, observedUtc),
                PolicyPriority = preferredPrefixes.Count > 0 && MatchesAnyPrefix(descriptor.Url, preferredPrefixes) ? 0 : 1,
                LastSuccessUtc = GetLastSuccessUtc(cursor, descriptor.Url),
                CircuitOpenUntilUtc = GetCircuitOpenUntilUtc(cursor, descriptor.Url)
            })
            .OrderBy(static row => row.HealthPriority)
            .ThenBy(static row => row.PolicyPriority)
            .ThenBy(static row => row.SelectedBoost)
            .ThenByDescending(static row => row.LastSuccessUtc ?? DateTimeOffset.MinValue)
            .ThenBy(static row => row.CircuitOpenUntilUtc ?? DateTimeOffset.MaxValue)
            .ThenBy(static row => row.Index)
            .Select(static row => row.Descriptor)
            .ToList();
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> ApplyLogSelectionPolicy(
        IReadOnlyList<ResolvedCtLogDescriptor> logDescriptors,
        NativeCtLogSubdomainDiscoveryOptions options) {
        if (logDescriptors == null || logDescriptors.Count == 0) {
            return Array.Empty<ResolvedCtLogDescriptor>();
        }

        var excludedPrefixes = NormalizeLogUrlPrefixes(options.ExcludedLogUrlPrefixes);
        var preferredPrefixes = NormalizeLogUrlPrefixes(options.PreferredLogUrlPrefixes);

        IEnumerable<ResolvedCtLogDescriptor> filtered = logDescriptors;
        if (excludedPrefixes.Count > 0) {
            filtered = filtered.Where(descriptor => !MatchesAnyPrefix(descriptor.Url, excludedPrefixes));
        }

        return filtered
            .Select((descriptor, index) => new {
                Descriptor = descriptor,
                Index = index,
                Preferred = preferredPrefixes.Count > 0 && MatchesAnyPrefix(descriptor.Url, preferredPrefixes)
            })
            .OrderBy(static row => row.Preferred ? 0 : 1)
            .ThenBy(static row => row.Index)
            .Select(static row => row.Descriptor)
            .ToList();
    }

    private static List<string> NormalizeLogUrlPrefixes(IReadOnlyList<string>? rawPrefixes) {
        if (rawPrefixes == null || rawPrefixes.Count == 0) {
            return new List<string>();
        }

        var normalized = new List<string>(rawPrefixes.Count);
        foreach (var rawPrefix in rawPrefixes) {
            var prefix = NormalizeLogUrl(rawPrefix);
            if (!string.IsNullOrWhiteSpace(prefix) &&
                !normalized.Contains(prefix, StringComparer.OrdinalIgnoreCase)) {
                normalized.Add(prefix!);
            }
        }

        return normalized;
    }

    private static bool MatchesAnyPrefix(string logUrl, IReadOnlyList<string> prefixes) {
        if (string.IsNullOrWhiteSpace(logUrl) || prefixes == null || prefixes.Count == 0) {
            return false;
        }

        foreach (var prefix in prefixes) {
            if (!string.IsNullOrWhiteSpace(prefix) &&
                logUrl.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) {
                return true;
            }
        }

        return false;
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> BuildExtendedProcessingOrder(
        IReadOnlyList<ResolvedCtLogDescriptor> logs,
        int maxLogsToProcess,
        bool prioritizeLatestExactMatch) {
        IReadOnlyList<ResolvedCtLogDescriptor> prioritized = ApplyLogCap(logs, maxLogsToProcess, prioritizeLatestExactMatch);
        IReadOnlyList<ResolvedCtLogDescriptor> uncapped = ApplyLogCap(logs, 0, prioritizeLatestExactMatch);
        if (prioritized.Count == 0) {
            return uncapped;
        }

        var ordered = new List<ResolvedCtLogDescriptor>(uncapped.Count);
        var selectedUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (ResolvedCtLogDescriptor descriptor in prioritized) {
            if (selectedUrls.Add(descriptor.Url)) {
                ordered.Add(descriptor);
            }
        }

        foreach (ResolvedCtLogDescriptor descriptor in uncapped) {
            if (selectedUrls.Add(descriptor.Url)) {
                ordered.Add(descriptor);
            }
        }

        return ordered;
    }

    private static int ClassifyLogHealthPriority(
        NativeCtCursorState cursor,
        string logUrl,
        DateTimeOffset observedUtc) {
        if (!cursor.TryGetLogHealthSnapshot(logUrl, out NativeCtCursorEntrySnapshot snapshot)) {
            return 1;
        }

        if (snapshot.CircuitOpenUntilUtc.HasValue && snapshot.CircuitOpenUntilUtc.Value > observedUtc) {
            return 4;
        }

        if (snapshot.LastSuccessUtc.HasValue &&
            (!snapshot.LastAttemptUtc.HasValue || snapshot.LastSuccessUtc.Value >= snapshot.LastAttemptUtc.Value)) {
            return 0;
        }

        if (!snapshot.LastAttemptUtc.HasValue) {
            return 1;
        }

        return IsLikelyPermanentNativeCtFailure(snapshot.LastError)
            ? 3
            : 2;
    }

    private static DateTimeOffset? GetLastSuccessUtc(NativeCtCursorState cursor, string logUrl) {
        return cursor.TryGetLogHealthSnapshot(logUrl, out NativeCtCursorEntrySnapshot snapshot)
            ? snapshot.LastSuccessUtc
            : null;
    }

    private static DateTimeOffset? GetCircuitOpenUntilUtc(NativeCtCursorState cursor, string logUrl) {
        return cursor.TryGetLogHealthSnapshot(logUrl, out NativeCtCursorEntrySnapshot snapshot)
            ? snapshot.CircuitOpenUntilUtc
            : null;
    }

    private async Task<int> PopulateDescriptorsFromLogListAsync(
        string logListUrl,
        NativeCtLogSubdomainDiscoveryOptions options,
        IDictionary<string, ResolvedCtLogDescriptor> descriptors,
        CancellationToken cancellationToken,
        int sourceOrder) {
        if (string.IsNullOrWhiteSpace(logListUrl)) {
            return sourceOrder;
        }

        var json = await FetchJsonWithRetryAsync(logListUrl, options, cancellationToken).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object) {
            return sourceOrder;
        }

        if (root.TryGetProperty("operators", out var operatorsElement) && operatorsElement.ValueKind == JsonValueKind.Array) {
            foreach (var op in operatorsElement.EnumerateArray()) {
                if (op.ValueKind != JsonValueKind.Object) {
                    continue;
                }
                if (!op.TryGetProperty("logs", out var logsElement) || logsElement.ValueKind != JsonValueKind.Array) {
                    continue;
                }
                foreach (var log in logsElement.EnumerateArray()) {
                    TryAddLogFromListItem(log, options, descriptors, ref sourceOrder);
                }
            }
            return sourceOrder;
        }

        if (root.TryGetProperty("logs", out var legacyLogs) && legacyLogs.ValueKind == JsonValueKind.Array) {
            foreach (var log in legacyLogs.EnumerateArray()) {
                TryAddLogFromListItem(log, options, descriptors, ref sourceOrder);
            }
        }

        return sourceOrder;
    }

    internal static IReadOnlyList<string> ApplyLogCap(
        IReadOnlyList<(string Url, DateTimeOffset? TemporalStartUtc, DateTimeOffset? TemporalEndUtc)> logs,
        int maxLogsToProcess) {
        return ApplyLogCap(logs, maxLogsToProcess, prioritizeLatestExactMatch: false);
    }

    internal static IReadOnlyList<string> ApplyLogCap(
        IReadOnlyList<(string Url, DateTimeOffset? TemporalStartUtc, DateTimeOffset? TemporalEndUtc)> logs,
        int maxLogsToProcess,
        bool prioritizeLatestExactMatch) {
        if (logs == null || logs.Count == 0) {
            return Array.Empty<string>();
        }

        var descriptors = new List<ResolvedCtLogDescriptor>(logs.Count);
        for (var i = 0; i < logs.Count; i++) {
            var log = logs[i];
            if (string.IsNullOrWhiteSpace(log.Url)) {
                continue;
            }

            descriptors.Add(new ResolvedCtLogDescriptor {
                Url = log.Url,
                TemporalStartUtc = log.TemporalStartUtc,
                TemporalEndUtc = log.TemporalEndUtc,
                SourceOrder = i
            });
        }

        return ApplyLogCap(descriptors, maxLogsToProcess, prioritizeLatestExactMatch)
            .Select(static descriptor => descriptor.Url)
            .ToList();
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> ApplyLogCap(
        IReadOnlyList<ResolvedCtLogDescriptor> logs,
        int maxLogsToProcess,
        bool prioritizeLatestExactMatch) {
        IReadOnlyList<ResolvedCtLogDescriptor> normalizedLogs = logs
            .Where(static log => log != null && !string.IsNullOrWhiteSpace(log.Url))
            .ToList();
        if (normalizedLogs.Count == 0) {
            return Array.Empty<ResolvedCtLogDescriptor>();
        }

        bool containsRetiredLogs = normalizedLogs.Any(static log => log.IsRetired);
        if (!containsRetiredLogs) {
            return ApplyLogCapWithoutRetiredBias(normalizedLogs, maxLogsToProcess, prioritizeLatestExactMatch);
        }

        var currentLogs = normalizedLogs
            .Where(static log => !log.IsRetired)
            .ToList();
        var retiredLogs = normalizedLogs
            .Where(static log => log.IsRetired)
            .ToList();

        if (retiredLogs.Count == 0) {
            return ApplyLogCapWithoutRetiredBias(currentLogs, maxLogsToProcess, prioritizeLatestExactMatch);
        }

        if (maxLogsToProcess <= 0 || normalizedLogs.Count <= maxLogsToProcess) {
            var orderedCurrent = ApplyLogCapWithoutRetiredBias(currentLogs, 0, prioritizeLatestExactMatch);
            var orderedRetired = ApplyLogCapWithoutRetiredBias(retiredLogs, 0, prioritizeLatestExactMatch: true);
            return orderedCurrent.Concat(orderedRetired).ToList();
        }

        int retiredBudget = Math.Min(retiredLogs.Count, ComputeHistoricalRetiredLogBudget(maxLogsToProcess));
        int currentBudget = Math.Max(0, maxLogsToProcess - retiredBudget);

        var selected = new List<ResolvedCtLogDescriptor>(maxLogsToProcess);
        var selectedUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (ResolvedCtLogDescriptor descriptor in ApplyLogCapWithoutRetiredBias(
                     currentLogs,
                     currentBudget,
                     prioritizeLatestExactMatch: true))
        {
            if (selected.Count >= maxLogsToProcess) {
                break;
            }

            if (selectedUrls.Add(descriptor.Url)) {
                selected.Add(descriptor);
            }
        }

        foreach (ResolvedCtLogDescriptor descriptor in ApplyLogCapWithoutRetiredBias(
                     retiredLogs,
                     retiredBudget,
                     prioritizeLatestExactMatch: true))
        {
            if (selected.Count >= maxLogsToProcess) {
                break;
            }

            if (selectedUrls.Add(descriptor.Url)) {
                selected.Add(descriptor);
            }
        }

        if (selected.Count < maxLogsToProcess) {
            foreach (ResolvedCtLogDescriptor descriptor in ApplyLogCapWithoutRetiredBias(
                         retiredLogs,
                         0,
                         prioritizeLatestExactMatch: true))
            {
                if (selected.Count >= maxLogsToProcess) {
                    break;
                }

                if (selectedUrls.Add(descriptor.Url)) {
                    selected.Add(descriptor);
                }
            }
        }

        return selected;
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> FilterLogsForCurrentQuery(
        IReadOnlyList<ResolvedCtLogDescriptor> logs,
        DateTimeOffset observedUtc) {
        if (logs == null || logs.Count == 0) {
            return Array.Empty<ResolvedCtLogDescriptor>();
        }

        var eligible = logs
            .Where(log => log != null && !IsFutureLog(log, observedUtc))
            .ToList();

        return eligible;
    }

    private static bool IsFutureLog(ResolvedCtLogDescriptor log, DateTimeOffset observedUtc) {
        if (log == null || !log.TemporalStartUtc.HasValue) {
            return false;
        }

        return log.TemporalStartUtc.Value > observedUtc;
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> ApplyLogCapWithoutRetiredBias(
        IReadOnlyList<ResolvedCtLogDescriptor> logs,
        int maxLogsToProcess,
        bool prioritizeLatestExactMatch) {
        var ordered = logs
            .OrderBy(static log => log.SourceOrder)
            .ThenBy(static log => log.Url, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var dated = ordered
            .Where(static log => log.TemporalStartUtc.HasValue || log.TemporalEndUtc.HasValue)
            .OrderBy(static log => log.TemporalStartUtc ?? log.TemporalEndUtc ?? DateTimeOffset.MinValue)
            .ThenBy(static log => log.TemporalEndUtc ?? DateTimeOffset.MaxValue)
            .ThenBy(static log => log.Url, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var undated = ordered
            .Where(static log => !log.TemporalStartUtc.HasValue && !log.TemporalEndUtc.HasValue)
            .ToList();

        if (maxLogsToProcess <= 0 || ordered.Count <= maxLogsToProcess) {
            return prioritizeLatestExactMatch
                ? BuildLatestFirstProcessingOrder(dated, undated)
                : BuildDistributedProcessingOrder(dated, undated);
        }

        var selected = new List<ResolvedCtLogDescriptor>(maxLogsToProcess);
        var selectedUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (dated.Count > 0) {
            foreach (var index in SelectEvenlyDistributedIndices(dated.Count, Math.Min(maxLogsToProcess, dated.Count))) {
                var descriptor = dated[index];
                if (selectedUrls.Add(descriptor.Url)) {
                    selected.Add(descriptor);
                }
            }
        }

        foreach (var descriptor in ordered) {
            if (selected.Count >= maxLogsToProcess) {
                break;
            }

            if (selectedUrls.Add(descriptor.Url)) {
                selected.Add(descriptor);
            }
        }

        var selectedDated = selected
            .Where(static log => log.TemporalStartUtc.HasValue || log.TemporalEndUtc.HasValue)
            .OrderBy(static log => log.TemporalStartUtc ?? log.TemporalEndUtc ?? DateTimeOffset.MinValue)
            .ThenBy(static log => log.TemporalEndUtc ?? DateTimeOffset.MaxValue)
            .ThenBy(static log => log.Url, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var selectedUndated = selected
            .Where(static log => !log.TemporalStartUtc.HasValue && !log.TemporalEndUtc.HasValue)
            .OrderBy(static log => log.SourceOrder)
            .ThenBy(static log => log.Url, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return prioritizeLatestExactMatch
            ? BuildLatestFirstProcessingOrder(selectedDated, selectedUndated)
            : BuildDistributedProcessingOrder(selectedDated, selectedUndated);
    }

    private static int ComputeHistoricalRetiredLogBudget(int maxLogsToProcess) {
        if (maxLogsToProcess <= 1) {
            return 0;
        }

        return Math.Max(1, maxLogsToProcess / 6);
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> BuildDistributedProcessingOrder(
        IReadOnlyList<ResolvedCtLogDescriptor> dated,
        IReadOnlyList<ResolvedCtLogDescriptor> undated) {
        var output = new List<ResolvedCtLogDescriptor>((dated?.Count ?? 0) + (undated?.Count ?? 0));
        if (dated != null && dated.Count > 0) {
            var left = 0;
            var right = dated.Count - 1;
            while (left <= right) {
                output.Add(dated[left]);
                if (right != left) {
                    output.Add(dated[right]);
                }
                left++;
                right--;
            }
        }

        if (undated != null && undated.Count > 0) {
            output.AddRange(undated);
        }

        return output;
    }

    private static IReadOnlyList<ResolvedCtLogDescriptor> BuildLatestFirstProcessingOrder(
        IReadOnlyList<ResolvedCtLogDescriptor> dated,
        IReadOnlyList<ResolvedCtLogDescriptor> undated) {
        var output = new List<ResolvedCtLogDescriptor>((dated?.Count ?? 0) + (undated?.Count ?? 0));
        if (dated != null && dated.Count > 0) {
            output.AddRange(dated
                .OrderByDescending(static log => log.TemporalEndUtc ?? log.TemporalStartUtc ?? DateTimeOffset.MinValue)
                .ThenByDescending(static log => log.TemporalStartUtc ?? DateTimeOffset.MinValue)
                .ThenBy(static log => log.SourceOrder)
                .ThenBy(static log => log.Url, StringComparer.OrdinalIgnoreCase));
        }

        if (undated != null && undated.Count > 0) {
            output.AddRange(undated
                .OrderBy(static log => log.SourceOrder)
                .ThenBy(static log => log.Url, StringComparer.OrdinalIgnoreCase));
        }

        return output;
    }

    private static void TryAddLogFromListItem(
        JsonElement log,
        NativeCtLogSubdomainDiscoveryOptions options,
        IDictionary<string, ResolvedCtLogDescriptor> descriptors,
        ref int sourceOrder) {
        if (log.ValueKind != JsonValueKind.Object) {
            return;
        }
        if (!ShouldIncludeLog(log, options.IncludePendingLogs, options.IncludeRetiredLogs)) {
            return;
        }
        var description = GetString(log, "description");
        var url = GetString(log, "url");
        var normalized = NormalizeLogUrl(url);
        if (normalized != null &&
            !IsKnownBogusLog(normalized, description)) {
            TryGetTemporalInterval(log, out var temporalStartUtc, out var temporalEndUtc);
            AddResolvedLogDescriptor(
                descriptors,
                normalized,
                temporalStartUtc,
                temporalEndUtc,
                IsRetiredLog(log),
                sourceOrder++);
        }
    }

    private static void AddResolvedLogDescriptor(
        IDictionary<string, ResolvedCtLogDescriptor> descriptors,
        string url,
        DateTimeOffset? temporalStartUtc,
        DateTimeOffset? temporalEndUtc,
        bool isRetired,
        int sourceOrder) {
        if (string.IsNullOrWhiteSpace(url)) {
            return;
        }

        if (descriptors.TryGetValue(url, out var existing)) {
            descriptors[url] = new ResolvedCtLogDescriptor {
                Url = url,
                TemporalStartUtc = existing.TemporalStartUtc ?? temporalStartUtc,
                TemporalEndUtc = existing.TemporalEndUtc ?? temporalEndUtc,
                IsRetired = existing.IsRetired || isRetired,
                SourceOrder = Math.Min(existing.SourceOrder, sourceOrder)
            };
            return;
        }

        descriptors[url] = new ResolvedCtLogDescriptor {
            Url = url,
            TemporalStartUtc = temporalStartUtc,
            TemporalEndUtc = temporalEndUtc,
            IsRetired = isRetired,
            SourceOrder = sourceOrder
        };
    }

    private static void TryGetTemporalInterval(
        JsonElement log,
        out DateTimeOffset? temporalStartUtc,
        out DateTimeOffset? temporalEndUtc) {
        temporalStartUtc = null;
        temporalEndUtc = null;
        if (!log.TryGetProperty("temporal_interval", out var temporalInterval) || temporalInterval.ValueKind != JsonValueKind.Object) {
            return;
        }

        temporalStartUtc = ParseCtLogIntervalTimestamp(
            GetString(temporalInterval, "start_inclusive") ??
            GetString(temporalInterval, "start"));
        temporalEndUtc = ParseCtLogIntervalTimestamp(
            GetString(temporalInterval, "end_exclusive") ??
            GetString(temporalInterval, "end_inclusive") ??
            GetString(temporalInterval, "end"));
    }

    private static DateTimeOffset? ParseCtLogIntervalTimestamp(string? value) {
        if (string.IsNullOrWhiteSpace(value)) {
            return null;
        }

        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed
            : null;
    }

    private static IReadOnlyList<int> SelectEvenlyDistributedIndices(int totalCount, int selectionCount) {
        if (totalCount <= 0 || selectionCount <= 0) {
            return Array.Empty<int>();
        }

        if (selectionCount >= totalCount) {
            return Enumerable.Range(0, totalCount).ToList();
        }

        if (selectionCount == 1) {
            return new[] { totalCount - 1 };
        }

        var selected = new List<int>(selectionCount);
        for (var i = 0; i < selectionCount; i++) {
            var index = (int)Math.Round(i * (totalCount - 1d) / (selectionCount - 1d), MidpointRounding.AwayFromZero);
            if (selected.Count == 0 || selected[selected.Count - 1] != index) {
                selected.Add(index);
            }
        }

        var cursor = 0;
        while (selected.Count < selectionCount && cursor < totalCount) {
            if (!selected.Contains(cursor)) {
                selected.Add(cursor);
            }
            cursor++;
        }

        selected.Sort();
        return selected;
    }

    private static bool ShouldIncludeLog(JsonElement log, bool includePendingLogs, bool includeRetiredLogs) {
        if (!log.TryGetProperty("state", out var state) || state.ValueKind != JsonValueKind.Object) {
            return true;
        }

        if (state.TryGetProperty("rejected", out _)) {
            return false;
        }
        if (state.TryGetProperty("retired", out _)) {
            return includeRetiredLogs;
        }
        if (state.TryGetProperty("usable", out _)) {
            return true;
        }
        if (state.TryGetProperty("qualified", out _)) {
            return true;
        }
        if (state.TryGetProperty("readonly", out _)) {
            return true;
        }
        if (state.TryGetProperty("pending", out _)) {
            return includePendingLogs;
        }

        return true;
    }

    private static bool IsRetiredLog(JsonElement log) {
        if (!log.TryGetProperty("state", out var state) || state.ValueKind != JsonValueKind.Object) {
            return false;
        }

        return state.TryGetProperty("retired", out _);
    }

    private static bool IsKnownBogusLog(string normalizedUrl, string? description) {
        if (string.IsNullOrWhiteSpace(normalizedUrl)) {
            return false;
        }

        if (normalizedUrl.StartsWith(KnownBogusCtLogUrlPrefix, StringComparison.OrdinalIgnoreCase)) {
            return true;
        }

        return !string.IsNullOrWhiteSpace(description) &&
               description!.Contains("Bogus RFC6962 log", StringComparison.OrdinalIgnoreCase);
    }

}
