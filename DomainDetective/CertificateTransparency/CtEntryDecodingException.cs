using System;

namespace DomainDetective;

/// <summary>A fetched entry could not be decoded. The raw bytes identify the range that must be retried.</summary>
public sealed class CtEntryDecodingException : InvalidOperationException {
    /// <summary>Initializes a failure containing the original leaf and extra data.</summary>
    public CtEntryDecodingException(string logUrl, long entryIndex, RawCtEntryPayload payload, string reason, Exception? innerException = null)
        : base($"CT entry {entryIndex} from {logUrl} could not be decoded: {reason}", innerException) {
        LogUrl = logUrl;
        EntryIndex = entryIndex;
        Payload = payload;
    }

    /// <summary>Log identity whose range must be retried.</summary>
    public string LogUrl { get; }
    /// <summary>Exact failed entry index.</summary>
    public long EntryIndex { get; }
    /// <summary>Original Merkle leaf and extra data for durable recovery.</summary>
    public RawCtEntryPayload Payload { get; }
    /// <summary>Original Static CT TileLeaf, when the failure came from a Static CT reader.</summary>
    public string? StaticTileEntryBase64 { get; init; }
}
