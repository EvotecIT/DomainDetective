using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;

namespace DomainDetective;

/// <summary>
/// Signed tree head metadata for one CT log at a point in time.
/// </summary>
/// <param name="TreeSize">Current tree size reported by the CT log.</param>
/// <param name="ObservedAtUtc">UTC time when the tree head was read or refreshed locally.</param>
public sealed record CtSignedTreeHead(
    long TreeSize,
    DateTimeOffset ObservedAtUtc) {
    /// <summary>Base64 SHA-256 Merkle root. Present on cryptographically verified tree heads.</summary>
    public string? RootHashBase64 { get; init; }
    /// <summary>Log-signed timestamp in milliseconds since the Unix epoch.</summary>
    public long? TimestampMilliseconds { get; init; }
    /// <summary>RFC6962 DigitallySigned structure encoded as base64.</summary>
    public string? SignatureBase64 { get; init; }
}

/// <summary>
/// Raw RFC6962 entry payload as returned by <c>get-entries</c>.
/// </summary>
/// <param name="LeafInputBase64">Base64-encoded Merkle leaf.</param>
/// <param name="ExtraDataBase64">Base64-encoded extra data payload.</param>
public sealed record RawCtEntryPayload(
    string LeafInputBase64,
    string ExtraDataBase64);

/// <summary>
/// Certificate Transparency entry type encoded in the Merkle tree leaf.
/// </summary>
public enum CtLogEntryType {
    /// <summary>Unknown or unsupported CT entry type.</summary>
    Unknown = -1,
    /// <summary>X.509 certificate entry.</summary>
    X509 = 0,
    /// <summary>Precertificate entry.</summary>
    Precertificate = 1
}

/// <summary>
/// Describes the CT log read API used by an endpoint.
/// </summary>
public enum CtLogApiKind {
    /// <summary>RFC6962 JSON APIs such as <c>get-sth</c> and <c>get-entries</c>.</summary>
    Rfc6962 = 0,
    /// <summary>Static CT monitoring API with checkpoints and immutable data tiles.</summary>
    StaticCt = 1
}

/// <summary>
/// Describes one CT log endpoint.
/// </summary>
public sealed class CtLogDescriptor {
    /// <summary>Base CT log URL.</summary>
    public string Url { get; init; } = string.Empty;
    /// <summary>Base64 CT log ID when supplied by an authoritative log list.</summary>
    public string? LogId { get; init; }
    /// <summary>Base64 public key when supplied by an authoritative log list.</summary>
    public string? PublicKey { get; init; }
    /// <summary>Maximum merge delay in seconds when supplied by an authoritative log list.</summary>
    public int? MaximumMergeDelaySeconds { get; init; }
    /// <summary>Read API used by this log.</summary>
    public CtLogApiKind ApiKind { get; init; } = CtLogApiKind.Rfc6962;
    /// <summary>Static CT monitoring prefix when <see cref="ApiKind"/> is <see cref="CtLogApiKind.StaticCt"/>.</summary>
    public string? MonitoringUrl { get; init; }
    /// <summary>Static CT submission prefix, or the RFC6962 base URL.</summary>
    public string? SubmissionUrl { get; init; }
    /// <summary>Human-readable CT log operator name when supplied by the log list.</summary>
    public string? OperatorName { get; init; }
    /// <summary>Human-readable log description when available.</summary>
    public string? Description { get; init; }
    /// <summary>Policy state supplied by the log list, for example usable, qualified, pending, retired, or rejected.</summary>
    public string? State { get; init; }
    /// <summary>True when the log list marks this log as retired.</summary>
    public bool IsRetired { get; init; }
    /// <summary>Inclusive lower bound of certificate expiration dates accepted by the shard.</summary>
    public DateTimeOffset? TemporalStartUtc { get; init; }
    /// <summary>Exclusive upper bound of certificate expiration dates accepted by the shard.</summary>
    public DateTimeOffset? TemporalEndUtc { get; init; }
    /// <summary>True when the log list marks this log read-only.</summary>
    public bool IsReadOnly => IsState("readonly");
    /// <summary>True when the log list marks this log pending.</summary>
    public bool IsPending => IsState("pending");
    /// <summary>True when the log list marks this log rejected.</summary>
    public bool IsRejected => IsState("rejected");
    /// <summary>True when the log list marks this log usable.</summary>
    public bool IsUsable => IsState("usable");
    /// <summary>True when the log list marks this log qualified.</summary>
    public bool IsQualified => IsState("qualified");

    private bool IsState(string state)
        => string.Equals(State?.Trim(), state, StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Represents a decoded CT log entry suitable for durable ingestion.
/// </summary>
public sealed class CtLogIngestionEntry {
    /// <summary>Base CT log URL.</summary>
    public string LogUrl { get; init; } = string.Empty;
    /// <summary>Entry index in the CT log.</summary>
    public long EntryIndex { get; init; }
    /// <summary>Tree size observed before fetching this entry batch.</summary>
    public long TreeSize { get; init; }
    /// <summary>CT entry timestamp from the Merkle tree leaf.</summary>
    public DateTimeOffset? EntryTimestampUtc { get; init; }
    /// <summary>Decoded CT entry type.</summary>
    public CtLogEntryType EntryType { get; init; } = CtLogEntryType.Unknown;
    /// <summary>True when this record came from a precertificate entry.</summary>
    public bool IsPrecertificate => EntryType == CtLogEntryType.Precertificate;
    /// <summary>Normalized certificate record derived from the CT entry DER bytes.</summary>
    public CtCertificateRecord Certificate { get; init; } = new();
}

/// <summary>
/// Represents one fetched CT log batch.
/// </summary>
public sealed class CtLogIngestionBatch {
    /// <summary>Verified tree head anchoring every returned raw entry when verification is required.</summary>
    public CtSignedTreeHead? VerifiedTreeHead { get; init; }
    /// <summary>Base CT log URL.</summary>
    public string LogUrl { get; init; } = string.Empty;
    /// <summary>Tree size observed before fetching this batch.</summary>
    public long TreeSize { get; init; }
    /// <summary>Requested first entry index.</summary>
    public long StartIndex { get; init; }
    /// <summary>Requested last entry index.</summary>
    public long EndIndex { get; init; }
    /// <summary>Decoded certificate entries.</summary>
    public IReadOnlyList<CtLogIngestionEntry> Entries { get; init; } = Array.Empty<CtLogIngestionEntry>();
    /// <summary>Diagnostics for skipped or undecodable CT entries.</summary>
    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Options for one CT log batch read.
/// </summary>
public sealed class CtLogIngestionBatchRequest {
    /// <summary>Base64 SubjectPublicKeyInfo from the trusted log catalog.</summary>
    public string? PublicKey { get; init; }
    /// <summary>Base64 SHA-256 log ID from the trusted log catalog.</summary>
    public string? LogId { get; init; }
    /// <summary>Submission prefix whose origin signs a Static CT checkpoint.</summary>
    public string? SubmissionUrl { get; init; }
    /// <summary>Requires a pinned signature, range inclusion, and consistency with the previous tree head.</summary>
    public bool RequireIntegrityVerification { get; init; }
    /// <summary>Last durable verified tree head for this log, used to reject rollback or inconsistent growth.</summary>
    public CtSignedTreeHead? PreviousTreeHead { get; init; }
    /// <summary>Throws on any undecodable entry so callers cannot advance past a missing certificate.</summary>
    public bool RequireCompleteDecoding { get; init; }
    /// <summary>Base CT log URL.</summary>
    public string LogUrl { get; init; } = string.Empty;
    /// <summary>Read API used by this log.</summary>
    public CtLogApiKind ApiKind { get; init; } = CtLogApiKind.Rfc6962;
    /// <summary>Static CT monitoring prefix used for checkpoint and tile reads.</summary>
    public string? MonitoringUrl { get; init; }
    /// <summary>First entry index to fetch.</summary>
    public long StartIndex { get; init; }
    /// <summary>Maximum entries to request. RFC6962 logs may return fewer entries.</summary>
    public int BatchSize { get; init; } = 256;
    /// <summary>
    /// Optional signed tree size already obtained by the caller. When supplied, the batch read skips
    /// an additional <c>get-sth</c> request and trusts this tree size for range clamping. Callers
    /// should only supply a fresh value because a stale tree size can delay discovery of newer log
    /// entries until a later refresh. Ignored when integrity verification is required.
    /// </summary>
    public long? KnownTreeSize { get; init; }
    /// <summary>HTTP request timeout.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>Maximum number of Static CT data tiles to fetch concurrently for one batch.</summary>
    public int StaticTileFetchConcurrency { get; init; } = 1;
    /// <summary>How much certificate metadata to decode for each entry.</summary>
    public CtCertificateRecordDetailLevel CertificateDetailLevel { get; init; } = CtCertificateRecordDetailLevel.Full;
}
