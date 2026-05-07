using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

/// <summary>
/// Compares portfolio snapshots and emits deterministic storage-friendly change rows.
/// </summary>
public static class DomainPortfolioSnapshotDiffer {
    private const int SupportedSchemaVersion = 1;

    /// <summary>
    /// Compares two portfolio snapshots with the supported schema version. Persisted snapshots should be migrated before diffing after a schema bump.
    /// </summary>
    /// <param name="previous">Previous snapshot.</param>
    /// <param name="current">Current snapshot.</param>
    /// <returns>Change set containing section and fact changes.</returns>
    public static DomainPortfolioChangeSet Compare(DomainPortfolioSnapshot previous, DomainPortfolioSnapshot current) {
        if (previous == null) throw new ArgumentNullException(nameof(previous));
        if (current == null) throw new ArgumentNullException(nameof(current));
        ValidateSchemaVersion(previous, nameof(previous));
        ValidateSchemaVersion(current, nameof(current));

        var previousSubject = previous.Subject?.Trim() ?? string.Empty;
        var currentSubject = current.Subject?.Trim() ?? string.Empty;
        if (!string.Equals(previousSubject, currentSubject, StringComparison.OrdinalIgnoreCase)) {
            throw new ArgumentException("Portfolio snapshots must have the same subject.", nameof(current));
        }

        var result = new DomainPortfolioChangeSet {
            Subject = previousSubject,
            PreviousCapturedAtUtc = previous.CapturedAtUtc,
            CurrentCapturedAtUtc = current.CapturedAtUtc
        };

        var previousSections = BuildSectionMap(previous);
        var currentSections = BuildSectionMap(current);
        var sectionKeys = previousSections.Keys
            .Union(currentSections.Keys, StringComparer.OrdinalIgnoreCase)
            .OrderBy(static key => key, StringComparer.OrdinalIgnoreCase);

        foreach (var sectionKey in sectionKeys) {
            var hasPrevious = previousSections.TryGetValue(sectionKey, out var previousSection);
            var hasCurrent = currentSections.TryGetValue(sectionKey, out var currentSection);

            if (!hasPrevious && hasCurrent) {
                result.Changes.Add(BuildSectionChange(sectionKey, DomainPortfolioChangeKind.Added, null, currentSection!.Status));
                AddAddedFactChanges(result.Changes, sectionKey, BuildFactMap(currentSection));
                continue;
            }

            if (hasPrevious && !hasCurrent) {
                result.Changes.Add(BuildSectionChange(sectionKey, DomainPortfolioChangeKind.Removed, previousSection!.Status, null));
                AddRemovedFactChanges(result.Changes, sectionKey, BuildFactMap(previousSection));
                continue;
            }

            if (previousSection == null || currentSection == null) continue;
            // Status values are controlled by the snapshot builder, so case-only changes are not meaningful.
            if (!string.Equals(previousSection.Status, currentSection.Status, StringComparison.OrdinalIgnoreCase)) {
                result.Changes.Add(BuildSectionChange(sectionKey, DomainPortfolioChangeKind.Changed, previousSection.Status, currentSection.Status));
            }

            AddChangedFacts(result.Changes, sectionKey, BuildFactMap(previousSection), BuildFactMap(currentSection));
        }

        return result;
    }

    private static void ValidateSchemaVersion(DomainPortfolioSnapshot snapshot, string parameterName) {
        if (snapshot.SchemaVersion != SupportedSchemaVersion) {
            throw new NotSupportedException($"Portfolio snapshot schema version {snapshot.SchemaVersion} is not supported for {parameterName}.");
        }
    }

    private static Dictionary<string, DomainPortfolioSection> BuildSectionMap(DomainPortfolioSnapshot snapshot)
        => (snapshot.Sections ?? new List<DomainPortfolioSection>())
            .Where(static section => section != null && !string.IsNullOrWhiteSpace(section.Key))
            .GroupBy(static section => section.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                static group => group.Key,
                static group => DomainPortfolioUtilities.SinglePortfolioItem(group, "section", group.Key),
                StringComparer.OrdinalIgnoreCase);

    private static Dictionary<string, DomainPortfolioFact> BuildFactMap(DomainPortfolioSection section)
        => (section.Facts ?? new List<DomainPortfolioFact>())
            .Where(static fact => fact != null && !string.IsNullOrWhiteSpace(fact.Key))
            .GroupBy(static fact => fact.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                static group => group.Key,
                static group => DomainPortfolioUtilities.SinglePortfolioItem(group, "fact", group.Key),
                StringComparer.OrdinalIgnoreCase);

    private static DomainPortfolioChange BuildSectionChange(string sectionKey, DomainPortfolioChangeKind kind, string? previousValue, string? currentValue)
        => new() {
            Key = $"section:{sectionKey}:status",
            Kind = kind,
            SectionKey = sectionKey,
            PreviousValue = previousValue,
            CurrentValue = currentValue
        };

    private static DomainPortfolioChange BuildFactChange(string sectionKey, string factKey, DomainPortfolioChangeKind kind, string? previousValue, string? currentValue)
        => new() {
            Key = $"fact:{sectionKey}:{factKey}",
            Kind = kind,
            SectionKey = sectionKey,
            FactKey = factKey,
            PreviousValue = previousValue,
            CurrentValue = currentValue
        };

    private static void AddAddedFactChanges(
        List<DomainPortfolioChange> changes,
        string sectionKey,
        Dictionary<string, DomainPortfolioFact> facts) {
        foreach (var pair in facts.OrderBy(static item => item.Key, StringComparer.OrdinalIgnoreCase)) {
            changes.Add(BuildFactChange(
                sectionKey,
                pair.Key,
                DomainPortfolioChangeKind.Added,
                null,
                pair.Value.Value));
        }
    }

    private static void AddRemovedFactChanges(
        List<DomainPortfolioChange> changes,
        string sectionKey,
        Dictionary<string, DomainPortfolioFact> facts) {
        foreach (var pair in facts.OrderBy(static item => item.Key, StringComparer.OrdinalIgnoreCase)) {
            changes.Add(BuildFactChange(
                sectionKey,
                pair.Key,
                DomainPortfolioChangeKind.Removed,
                pair.Value.Value,
                null));
        }
    }

    private static void AddChangedFacts(
        List<DomainPortfolioChange> changes,
        string sectionKey,
        Dictionary<string, DomainPortfolioFact> previousFacts,
        Dictionary<string, DomainPortfolioFact> currentFacts) {
        var factKeys = previousFacts.Keys
            .Union(currentFacts.Keys, StringComparer.OrdinalIgnoreCase)
            .OrderBy(static key => key, StringComparer.OrdinalIgnoreCase);

        foreach (var factKey in factKeys) {
            var hasPrevious = previousFacts.TryGetValue(factKey, out var previousFact);
            var hasCurrent = currentFacts.TryGetValue(factKey, out var currentFact);
            if (!hasPrevious && hasCurrent) {
                changes.Add(BuildFactChange(sectionKey, factKey, DomainPortfolioChangeKind.Added, null, currentFact!.Value));
                continue;
            }

            if (hasPrevious && !hasCurrent) {
                changes.Add(BuildFactChange(sectionKey, factKey, DomainPortfolioChangeKind.Removed, previousFact!.Value, null));
                continue;
            }

            // Fact values are normalized storage values; preserve case-sensitive changes.
            if (!string.Equals(previousFact!.Value, currentFact!.Value, StringComparison.Ordinal)) {
                changes.Add(BuildFactChange(sectionKey, factKey, DomainPortfolioChangeKind.Changed, previousFact.Value, currentFact.Value));
            }
        }
    }
}
