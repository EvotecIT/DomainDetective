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

public sealed partial class CtLogIngestionClient {
    private static bool TryDecodeCertificate(
        RawCtEntryPayload payload,
        out DateTimeOffset? timestampUtc,
        out CtLogEntryType entryType,
        out byte[]? certificateDer,
        out string? diagnostic) {
        timestampUtc = null;
        entryType = CtLogEntryType.Unknown;
        certificateDer = null;
        diagnostic = null;

        byte[] leafBytes;
        try {
            leafBytes = Convert.FromBase64String(payload.LeafInputBase64);
        } catch (FormatException) {
            diagnostic = "leaf_input was not valid base64.";
            return false;
        }

        if (!TryParseLeaf(leafBytes, out timestampUtc, out int rawEntryType, out byte[]? x509Leaf)) {
            diagnostic = "leaf_input could not be parsed.";
            return false;
        }

        entryType = rawEntryType switch {
            X509EntryType => CtLogEntryType.X509,
            PrecertEntryType => CtLogEntryType.Precertificate,
            _ => CtLogEntryType.Unknown
        };

        if (rawEntryType == X509EntryType) {
            certificateDer = x509Leaf;
        } else if (rawEntryType == PrecertEntryType) {
            if (string.IsNullOrWhiteSpace(payload.ExtraDataBase64)) {
                diagnostic = "precertificate extra_data was empty.";
                return false;
            }

            try {
                certificateDer = TryExtractPrecertificateLeaf(Convert.FromBase64String(payload.ExtraDataBase64));
            } catch (FormatException) {
                diagnostic = "precertificate extra_data was not valid base64.";
                return false;
            }
        }

        if (certificateDer == null || certificateDer.Length == 0) {
            diagnostic = "entry did not contain certificate bytes.";
            return false;
        }

        return true;
    }

    private static IReadOnlyList<StaticCtTileEntry> ParseStaticDataTile(byte[] tileBytes, int expectedWidth, string monitoringUrl, long tileIndex) {
        if (tileBytes == null) {
            throw new ArgumentNullException(nameof(tileBytes));
        }

        var entries = new List<StaticCtTileEntry>(Math.Max(0, expectedWidth));
        int offset = 0;
        while (offset < tileBytes.Length) {
            int entryOffset = offset;
            if (!TryParseStaticTileLeaf(tileBytes, ref offset, out StaticCtTileEntry? entry)) {
                throw new CtDataTileDecodingException(monitoringUrl, tileIndex * StaticCtTileWidth + entries.Count, tileIndex,
                    Convert.ToBase64String(tileBytes), $"TileLeaf could not be parsed at byte offset {entryOffset}.");
            }

            entries.Add(entry!);
        }

        if (expectedWidth > 0 && entries.Count != expectedWidth) {
            throw new CtDataTileDecodingException(monitoringUrl, tileIndex * StaticCtTileWidth + Math.Min(entries.Count, expectedWidth), tileIndex,
                Convert.ToBase64String(tileBytes), $"Tile contained {entries.Count} entries but {expectedWidth} were expected.");
        }

        return entries;
    }

    private static bool TryParseStaticTileLeaf(byte[] data, ref int offset, out StaticCtTileEntry? entry) {
        entry = null;
        int startOffset = offset;
        if (!TryReadUInt64BigEndian(data, ref offset, out ulong timestampMs) ||
            !TryReadUInt16BigEndian(data, ref offset, out int rawEntryType)) {
            offset = startOffset;
            return false;
        }

        DateTimeOffset? timestampUtc;
        try {
            timestampUtc = DateTimeOffset.FromUnixTimeMilliseconds((long)timestampMs);
        } catch (ArgumentOutOfRangeException) {
            timestampUtc = null;
        }

        byte[]? certificateDer = null;
        CtLogEntryType entryType = rawEntryType switch {
            X509EntryType => CtLogEntryType.X509,
            PrecertEntryType => CtLogEntryType.Precertificate,
            _ => CtLogEntryType.Unknown
        };

        if (rawEntryType == X509EntryType) {
            if (!TryReadVector24(data, ref offset, out certificateDer)) {
                offset = startOffset;
                return false;
            }
        } else if (rawEntryType == PrecertEntryType) {
            if (offset + 32 > data.Length) {
                offset = startOffset;
                return false;
            }

            offset += 32;
            if (!TryReadVector24(data, ref offset, out _)) {
                offset = startOffset;
                return false;
            }
        } else {
            offset = startOffset;
            return false;
        }

        if (!TryReadVector16(data, ref offset, out _)) {
            offset = startOffset;
            return false;
        }

        byte[] leafInput = new byte[offset - startOffset + 2];
        Buffer.BlockCopy(data, startOffset, leafInput, 2, offset - startOffset);

        if (rawEntryType == PrecertEntryType &&
            !TryReadVector24(data, ref offset, out certificateDer)) {
            offset = startOffset;
            return false;
        }

        if (!TryReadVector16(data, ref offset, out byte[]? certificateChain)) {
            offset = startOffset;
            return false;
        }

        if (certificateDer == null || certificateDer.Length == 0 ||
            certificateChain == null ||
            certificateChain.Length % 32 != 0) {
            offset = startOffset;
            return false;
        }

        byte[] extraData = Array.Empty<byte>();
        if (entryType == CtLogEntryType.Precertificate) {
            extraData = new byte[certificateDer.Length + 6];
            extraData[0] = (byte)(certificateDer.Length >> 16);
            extraData[1] = (byte)(certificateDer.Length >> 8);
            extraData[2] = (byte)certificateDer.Length;
            Buffer.BlockCopy(certificateDer, 0, extraData, 3, certificateDer.Length);
        }
        byte[] rawData = new byte[offset - startOffset];
        Buffer.BlockCopy(data, startOffset, rawData, 0, rawData.Length);
        entry = new StaticCtTileEntry(timestampUtc, entryType, certificateDer, leafInput, extraData, certificateChain, rawData);
        return true;
    }

    private static bool TryParseLeaf(byte[] leafBytes, out DateTimeOffset? timestampUtc, out int entryType, out byte[]? x509LeafCertificate) {
        timestampUtc = null;
        entryType = -1;
        x509LeafCertificate = null;
        if (leafBytes == null || leafBytes.Length < 12) {
            return false;
        }

        int offset = 2;
        if (!TryReadUInt64BigEndian(leafBytes, ref offset, out ulong timestampMs) ||
            !TryReadUInt16BigEndian(leafBytes, ref offset, out entryType)) {
            return false;
        }

        try {
            timestampUtc = DateTimeOffset.FromUnixTimeMilliseconds((long)timestampMs);
        } catch (ArgumentOutOfRangeException) {
            timestampUtc = null;
        }

        if (entryType == X509EntryType) {
            return TryReadVector24(leafBytes, ref offset, out x509LeafCertificate);
        }

        if (entryType == PrecertEntryType) {
            if (offset + 32 > leafBytes.Length) {
                return false;
            }

            offset += 32;
            return TryReadVector24(leafBytes, ref offset, out _);
        }

        return false;
    }

    private static byte[]? TryExtractPrecertificateLeaf(byte[] extraData) {
        int offset = 0;
        return TryReadVector24(extraData, ref offset, out byte[]? certBytes) ? certBytes : null;
    }

    private static bool TryReadUInt16BigEndian(byte[] data, ref int offset, out int value) {
        value = 0;
        if (data == null || offset < 0 || offset + 2 > data.Length) {
            return false;
        }

        value = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        return true;
    }

    private static bool TryReadUInt64BigEndian(byte[] data, ref int offset, out ulong value) {
        value = 0;
        if (data == null || offset < 0 || offset + 8 > data.Length) {
            return false;
        }

        for (int i = 0; i < 8; i++) {
            value = (value << 8) | data[offset + i];
        }

        offset += 8;
        return true;
    }

    private static bool TryReadVector24(byte[] data, ref int offset, out byte[]? bytes) {
        bytes = null;
        if (!TryReadUInt24(data, ref offset, out int length) || length < 0 || offset + length > data.Length) {
            return false;
        }

        bytes = new byte[length];
        Buffer.BlockCopy(data, offset, bytes, 0, length);
        offset += length;
        return true;
    }

    private static bool TryReadVector16(byte[] data, ref int offset, out byte[]? bytes) {
        bytes = null;
        if (!TryReadUInt16BigEndian(data, ref offset, out int length) || length < 0 || offset + length > data.Length) {
            return false;
        }

        bytes = new byte[length];
        Buffer.BlockCopy(data, offset, bytes, 0, length);
        offset += length;
        return true;
    }

    private static bool TryReadUInt24(byte[] data, ref int offset, out int value) {
        value = 0;
        if (data == null || offset < 0 || offset + 3 > data.Length) {
            return false;
        }

        value = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
        offset += 3;
        return true;
    }

}
