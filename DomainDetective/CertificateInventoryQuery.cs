using System;
using System.Collections.Generic;

namespace DomainDetective {
    /// <summary>
    /// Query options for searching persisted certificate inventory snapshots.
    /// </summary>
    public sealed class CertificateInventoryQuery {
        public DateTimeOffset? SinceUtc { get; set; }
        public DateTimeOffset? UntilUtc { get; set; }
        public string? HostContains { get; set; }
        public string? ServiceEquals { get; set; }
        public string? IssuerContains { get; set; }
        public bool? KnownAuthorityOnly { get; set; }
        public bool? ExpiredOnly { get; set; }
        public int? ExpiringWithinDays { get; set; }
        public int MaxResults { get; set; } = 500;
    }

    /// <summary>
    /// One matching inventory entry with the snapshot capture timestamp.
    /// </summary>
    public sealed class CertificateInventoryObservedEntry {
        public DateTimeOffset CapturedAtUtc { get; set; }
        public CertificateInventoryEntry Entry { get; set; } = new();
    }

    /// <summary>
    /// Query response containing matched entries and high-level counters.
    /// </summary>
    public sealed class CertificateInventoryQueryResult {
        public int ScannedSnapshotCount { get; set; }
        public int ScannedEntryCount { get; set; }
        public int MatchedEntryCount { get; set; }
        public bool Truncated { get; set; }
        public List<CertificateInventoryObservedEntry> Entries { get; set; } = new();
    }
}
