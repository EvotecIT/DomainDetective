using System;

namespace DomainDetective;

/// <summary>A malformed Static CT data tile. Retaining its bytes allows a host to recover without skipping entries.</summary>
public sealed class CtDataTileDecodingException : InvalidOperationException {
    /// <summary>Initializes a failure with the original complete tile.</summary>
    public CtDataTileDecodingException(string monitoringUrl, long entryIndex, long tileIndex, string tileBase64, string reason)
        : base($"Static CT tile {tileIndex} from {monitoringUrl} could not be decoded at entry {entryIndex}: {reason}") {
        MonitoringUrl = monitoringUrl;
        EntryIndex = entryIndex;
        TileIndex = tileIndex;
        TileBase64 = tileBase64;
    }
    /// <summary>Monitoring prefix serving the malformed tile.</summary>
    public string MonitoringUrl { get; }
    /// <summary>First entry whose position or encoding could not be determined.</summary>
    public long EntryIndex { get; }
    /// <summary>Data tile index.</summary>
    public long TileIndex { get; }
    /// <summary>Base64 original tile bytes.</summary>
    public string TileBase64 { get; }
}
