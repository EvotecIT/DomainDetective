using System;
using System.Collections.Generic;

namespace DomainDetective {
    /// <summary>
    /// Query options for searching persisted certificate inventory snapshots.
    /// </summary>
    public sealed class CertificateInventoryQuery {
        /// <summary>Only include snapshots captured on or after this UTC timestamp.</summary>
        public DateTimeOffset? SinceUtc { get; set; }
        /// <summary>Only include snapshots captured on or before this UTC timestamp.</summary>
        public DateTimeOffset? UntilUtc { get; set; }
        /// <summary>Case-insensitive host substring filter.</summary>
        public string? HostContains { get; set; }
        /// <summary>Case-insensitive certificate subject substring filter.</summary>
        public string? SubjectContains { get; set; }
        /// <summary>Case-insensitive SAN substring filter.</summary>
        public string? SanContains { get; set; }
        /// <summary>Case-insensitive service name exact-match filter.</summary>
        public string? ServiceEquals { get; set; }
        /// <summary>Case-insensitive issuer substring filter.</summary>
        public string? IssuerContains { get; set; }
        /// <summary>Case-insensitive CA family exact-match filter for the leaf issuer.</summary>
        public string? AuthorityFamilyEquals { get; set; }
        /// <summary>Case-insensitive root issuer/subject substring filter.</summary>
        public string? RootContains { get; set; }
        /// <summary>Case-insensitive CA family exact-match filter for the root issuer.</summary>
        public string? RootAuthorityFamilyEquals { get; set; }
        /// <summary>Case-insensitive CT source substring filter (matches any configured discovery source).</summary>
        public string? CtSourceContains { get; set; }
        /// <summary>Case-insensitive CT template-error substring filter (matches any captured template/configuration error).</summary>
        public string? CtTemplateErrorContains { get; set; }
        /// <summary>Case-insensitive chain source substring filter (matches the latest or historical chain source).</summary>
        public string? ChainSourceContains { get; set; }
        /// <summary>Leaf certificate thumbprint exact-match filter.</summary>
        public string? ThumbprintEquals { get; set; }
        /// <summary>When set, include only entries whose recognized-authority state equals this value.</summary>
        public bool? KnownAuthorityOnly { get; set; }
        /// <summary>When set, include only entries whose recognized-root-authority state equals this value.</summary>
        public bool? KnownRootAuthorityOnly { get; set; }
        /// <summary>When set, include only entries whose certificate validity equals this value.</summary>
        public bool? ValidOnly { get; set; }
        /// <summary>When set, include only entries whose expiry state equals this value.</summary>
        public bool? ExpiredOnly { get; set; }
        /// <summary>When set, include only entries whose chain completeness equals this value.</summary>
        public bool? ChainCompleteOnly { get; set; }
        /// <summary>When set, include only entries whose hostname match state equals this value.</summary>
        public bool? HostnameMatchOnly { get; set; }
        /// <summary>When set, include only entries whose self-signed state equals this value.</summary>
        public bool? SelfSignedOnly { get; set; }
        /// <summary>When set, include only entries whose reachability equals this value.</summary>
        public bool? ReachableOnly { get; set; }
        /// <summary>When set, include only entries whose CT presence equals this value.</summary>
        public bool? PresentInCtOnly { get; set; }
        /// <summary>When set, include only entries whose server-auth EKU state equals this value.</summary>
        public bool? AllowsServerAuthOnly { get; set; }
        /// <summary>When set, include only entries whose client-auth EKU state equals this value.</summary>
        public bool? AllowsClientAuthOnly { get; set; }
        /// <summary>When set, include only entries whose secure-email EKU state equals this value.</summary>
        public bool? AllowsSecureEmailOnly { get; set; }
        /// <summary>When set, include only entries whose weak-key state equals this value.</summary>
        public bool? WeakKeyOnly { get; set; }
        /// <summary>When set, include only entries whose SHA-1 signature state equals this value.</summary>
        public bool? Sha1SignatureOnly { get; set; }
        /// <summary>
        /// When set, include only entries whose not-yet-valid state equals this value (NotBeforeUtc is in the future).
        /// Entries with no NotBeforeUtc value are treated as already valid.
        /// </summary>
        public bool? NotYetValidOnly { get; set; }
        /// <summary>Case-insensitive authentication profile exact-match filter.</summary>
        public string? AuthenticationProfileEquals { get; set; }
        /// <summary>Only include certificates expiring within this many days (future dates only).</summary>
        public int? ExpiringWithinDays { get; set; }
        /// <summary>
        /// When true, only evaluate the latest observed entry per endpoint (host+port) within the selected snapshot window.
        /// Older observations for that same endpoint are skipped even if they would otherwise match filters.
        /// </summary>
        public bool LatestPerEndpointOnly { get; set; }
        /// <summary>Maximum number of entries returned in <see cref="CertificateInventoryQueryResult.Entries"/>.</summary>
        public int MaxResults { get; set; } = 500;
    }

    /// <summary>
    /// One matching inventory entry with the snapshot capture timestamp.
    /// </summary>
    public sealed class CertificateInventoryObservedEntry {
        /// <summary>Snapshot timestamp where the entry was observed.</summary>
        public DateTimeOffset CapturedAtUtc { get; set; }
        /// <summary>Observed certificate inventory entry.</summary>
        public CertificateInventoryEntry Entry { get; set; } = new();
    }

    /// <summary>
    /// Query response containing matched entries and high-level counters.
    /// </summary>
    public sealed class CertificateInventoryQueryResult {
        /// <summary>
        /// Number of snapshots loaded for evaluation after <see cref="CertificateInventoryQuery.SinceUtc"/> filtering.
        /// Includes snapshots later skipped by <see cref="CertificateInventoryQuery.UntilUtc"/>.
        /// Snapshots excluded by <see cref="CertificateInventoryQuery.SinceUtc"/> are not counted separately.
        /// </summary>
        public int LoadedSnapshotCount { get; set; }
        /// <summary>Number of loaded snapshots skipped because they are newer than <see cref="CertificateInventoryQuery.UntilUtc"/>.</summary>
        public int SkippedSnapshotCountByUntilUtc { get; set; }
        /// <summary>Number of snapshots scanned after <see cref="CertificateInventoryQuery.UntilUtc"/> filtering.</summary>
        public int ScannedSnapshotCount { get; set; }
        /// <summary>Number of entries scanned.</summary>
        public int ScannedEntryCount { get; set; }
        /// <summary>Number of scanned entries skipped because an entry for the same endpoint was already evaluated in latest-only mode. Always 0 when latest-only mode is disabled.</summary>
        public int SkippedByLatestPerEndpointCount { get; set; }
        /// <summary>Number of entries evaluated against query filters after latest-only deduplication.</summary>
        public int EvaluatedEntryCount { get; set; }
        /// <summary>Number of evaluated entries excluded by query filters.</summary>
        public int ExcludedByFiltersCount { get; set; }
        /// <summary>Number of entries matching filters (including truncated matches).</summary>
        public int MatchedEntryCount { get; set; }
        /// <summary>Number of unique endpoints represented by matched entries (host+port key, including truncated matches).</summary>
        public int MatchedUniqueEndpointCount { get; set; }
        /// <summary>Number of matched entries omitted from <see cref="Entries"/> due to <see cref="CertificateInventoryQuery.MaxResults"/>.</summary>
        public int EntriesTruncatedByMaxResults { get; set; }
        /// <summary>Indicates whether matched results exceeded <see cref="CertificateInventoryQuery.MaxResults"/>.</summary>
        public bool Truncated { get; set; }
        /// <summary>Matched entries, limited by the configured maximum.</summary>
        public List<CertificateInventoryObservedEntry> Entries { get; set; } = new();
        /// <summary>Distribution of matched entries by service.</summary>
        public Dictionary<string, int> MatchedServiceCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Distribution of matched entries by normalized issuer.</summary>
        public Dictionary<string, int> MatchedIssuerCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Distribution of matched entries by normalized root issuer.</summary>
        public Dictionary<string, int> MatchedRootIssuerCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Distribution of matched entries by authentication profile.</summary>
        public Dictionary<string, int> MatchedAuthenticationProfileCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Distribution of matched entries by primary chain source.</summary>
        public Dictionary<string, int> MatchedChainSourceCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Distribution of matched entries by CT discovery source (one entry can increment multiple sources).</summary>
        public Dictionary<string, int> MatchedCtSourceCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Distribution of matched entries by CT template-error category.</summary>
        public Dictionary<string, int> MatchedCtTemplateErrorCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }
}
