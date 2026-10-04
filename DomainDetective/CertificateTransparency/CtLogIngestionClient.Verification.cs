using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace DomainDetective;

public sealed partial class CtLogIngestionClient {
    /// <summary>Verifies a tree head against its catalog key and proves growth from the last durable tree.</summary>
    public async Task<CtSignedTreeHead> GetVerifiedSignedTreeHeadAsync(CtLogDescriptor log, CtSignedTreeHead? previousTreeHead,
        TimeSpan timeout, CancellationToken cancellationToken = default) {
        if (log == null) throw new ArgumentNullException(nameof(log));
        byte[] key = DecodeRequiredBase64(log.PublicKey, "catalog public key");
        byte[] logId = DecodeRequiredBase64(log.LogId, "catalog log ID");
        CtMerkleTree.RequireHash(logId);
        if (!CtMerkleTree.Equal(CtMerkleTree.Hash(key), logId))
            throw new InvalidOperationException("CT catalog key does not match the pinned log ID.");
        string logUrl = NormalizeLogUrl(log.Url) ?? throw new ArgumentException("CT log URL must be absolute.", nameof(log));
        string monitoringUrl = NormalizeLogUrl(log.MonitoringUrl ?? log.Url) ?? throw new ArgumentException("CT monitoring URL must be absolute.", nameof(log));
        string origin = ToStaticCheckpointOrigin(NormalizeLogUrl(log.SubmissionUrl ?? log.Url) ?? logUrl);
        string cacheKey = "verified:" + log.ApiKind + ":" + monitoringUrl + ":" + origin + ":" + Convert.ToBase64String(logId);
        CtSignedTreeHead head;
        if (TryGetCachedSignedTreeHead(cacheKey, out CtSignedTreeHead cached) &&
            (previousTreeHead == null || cached.TreeSize >= previousTreeHead.TreeSize)) head = cached;
        else {
            if (log.ApiKind == CtLogApiKind.StaticCt) {
                string note = await FetchTextAsync(CombineLogUrl(monitoringUrl, "checkpoint"), timeout, cancellationToken).ConfigureAwait(false);
                head = VerifyStaticCheckpoint(note, origin, key, logId);
            } else {
                string json = await FetchJsonAsync(CombineLogUrl(logUrl, "ct/v1/get-sth"), timeout, cancellationToken).ConfigureAwait(false);
                using var document = JsonDocument.Parse(json);
                JsonElement root = document.RootElement;
                if (!TryGetInt64(root, "tree_size", out long size) || !TryGetInt64(root, "timestamp", out long timestamp))
                    throw new InvalidOperationException("CT signed tree head is missing tree size or timestamp.");
                head = VerifyTreeHead(size, timestamp, GetString(root, "sha256_root_hash"), GetString(root, "tree_head_signature"), key);
            }
            CacheSignedTreeHead(cacheKey, head);
        }
        if (previousTreeHead != null) {
            byte[] previousRoot = DecodeRequiredBase64(previousTreeHead.RootHashBase64, "previous verified root");
            byte[] currentRoot = DecodeRequiredBase64(head.RootHashBase64, "verified root");
            IReadOnlyList<byte[]> proof = Array.Empty<byte[]>();
            if (previousTreeHead.TreeSize > 0 && previousTreeHead.TreeSize < head.TreeSize) {
                if (log.ApiKind == CtLogApiKind.StaticCt) {
                    var tiles = new Dictionary<string, byte[]>();
                    var generated = new List<byte[]>();
                    await BuildStaticConsistencyProofAsync(monitoringUrl, previousTreeHead.TreeSize, head.TreeSize,
                        0, true, head.TreeSize, generated, tiles, timeout, cancellationToken).ConfigureAwait(false);
                    proof = generated;
                } else {
                    string json = await FetchJsonAsync(CombineLogUrl(logUrl, $"ct/v1/get-sth-consistency?first={previousTreeHead.TreeSize}&second={head.TreeSize}"), timeout, cancellationToken).ConfigureAwait(false);
                    using var document = JsonDocument.Parse(json);
                    proof = ParseProof(document.RootElement, "consistency");
                }
            }
            CtMerkleTree.VerifyConsistency(previousTreeHead.TreeSize, head.TreeSize, previousRoot, currentRoot, proof);
        }
        return head;
    }

    private static CtSignedTreeHead VerifyTreeHead(long size, long timestamp, string? rootBase64, string? signatureBase64, byte[] publicKey) {
        if (size < 0 || timestamp < 0) throw new InvalidOperationException("CT signed tree head has a negative size or timestamp.");
        byte[] root = DecodeRequiredBase64(rootBase64, "signed Merkle root");
        CtMerkleTree.RequireHash(root);
        if (size == 0 && !CtMerkleTree.Equal(root, CtMerkleTree.Hash(Array.Empty<byte>())))
            throw new InvalidOperationException("Empty CT tree has an invalid root.");
        byte[] signature = DecodeRequiredBase64(signatureBase64, "tree head signature");
        if (signature.Length < 5 || signature[0] != 4 || (signature[1] != 1 && signature[1] != 3))
            throw new InvalidOperationException("CT tree signature requires SHA-256 with RSA or ECDSA.");
        int signatureLength = (signature[2] << 8) | signature[3];
        if (signatureLength != signature.Length - 4) throw new InvalidOperationException("CT DigitallySigned length is invalid.");
        byte[] message = new byte[50];
        message[1] = 1; // v1, tree_hash signature type
        WriteUInt64(message, 2, checked((ulong)timestamp));
        WriteUInt64(message, 10, checked((ulong)size));
        Buffer.BlockCopy(root, 0, message, 18, 32);
        byte[] value = new byte[signatureLength];
        Buffer.BlockCopy(signature, 4, value, 0, signatureLength);
        AsymmetricKeyParameter key = PublicKeyFactory.CreateKey(publicKey);
        ISigner verifier = SignerUtilities.GetSigner(signature[1] == 1 ? "SHA256withRSA" : "SHA256withECDSA");
        verifier.Init(false, key);
        verifier.BlockUpdate(message, 0, message.Length);
        if (!verifier.VerifySignature(value)) throw new InvalidOperationException("CT signed tree head signature does not verify against the catalog key.");
        return new CtSignedTreeHead(size, DateTimeOffset.UtcNow) {
            RootHashBase64 = Convert.ToBase64String(root), TimestampMilliseconds = timestamp, SignatureBase64 = Convert.ToBase64String(signature)
        };
    }

    private static CtSignedTreeHead VerifyStaticCheckpoint(string note, string expectedOrigin, byte[] key, byte[] logId) {
        if (note.Contains("\r")) throw new InvalidOperationException("Static CT checkpoint must use canonical LF line endings.");
        string[] lines = note.Split('\n');
        if (lines.Length < 6 || lines[0] != expectedOrigin || lines[3].Length != 0 ||
            !long.TryParse(lines[1], NumberStyles.None, CultureInfo.InvariantCulture, out long size) || size < 0 || size > (1L << 40))
            throw new InvalidOperationException("Static CT checkpoint origin, size, or signed note layout is invalid.");
        byte[] identityPrefix = Encoding.UTF8.GetBytes(expectedOrigin + "\n");
        byte[] identity = new byte[identityPrefix.Length + 33];
        Buffer.BlockCopy(identityPrefix, 0, identity, 0, identityPrefix.Length);
        identity[identityPrefix.Length] = 5;
        Buffer.BlockCopy(logId, 0, identity, identityPrefix.Length + 1, 32);
        byte[] identityHash = CtMerkleTree.Hash(identity);
        string prefix = "\u2014 " + expectedOrigin + " ";
        for (int i = 4; i < lines.Length; i++) {
            if (!lines[i].StartsWith(prefix, StringComparison.Ordinal)) continue;
            byte[] signature = DecodeRequiredBase64(lines[i].Substring(prefix.Length), "checkpoint signature");
            if (signature.Length < 17 || signature[0] != identityHash[0] || signature[1] != identityHash[1] ||
                signature[2] != identityHash[2] || signature[3] != identityHash[3]) continue;
            int offset = 4;
            if (!TryReadUInt64BigEndian(signature, ref offset, out ulong timestamp) || timestamp > long.MaxValue)
                throw new InvalidOperationException("Static CT checkpoint timestamp is invalid.");
            byte[] digitallySigned = new byte[signature.Length - offset];
            Buffer.BlockCopy(signature, offset, digitallySigned, 0, digitallySigned.Length);
            return VerifyTreeHead(size, (long)timestamp, lines[2], Convert.ToBase64String(digitallySigned), key);
        }
        throw new InvalidOperationException("Static CT checkpoint has no signature from the pinned log key.");
    }

    private static void WriteUInt64(byte[] destination, int offset, ulong value) {
        for (int i = 7; i >= 0; i--) { destination[offset + i] = (byte)value; value >>= 8; }
    }

    private static byte[] DecodeRequiredBase64(string? value, string field) {
        if (string.IsNullOrWhiteSpace(value)) throw new InvalidOperationException($"CT {field} is missing.");
        try { return Convert.FromBase64String(value); }
        catch (FormatException ex) { throw new InvalidOperationException($"CT {field} is not valid base64.", ex); }
    }

    private static IReadOnlyList<byte[]> ParseProof(JsonElement root, string field) {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty(field, out JsonElement values) || values.ValueKind != JsonValueKind.Array)
            throw new InvalidOperationException($"CT proof response is missing {field}.");
        if (values.GetArrayLength() > 64) throw new InvalidOperationException("CT proof has too many hashes.");
        var result = new List<byte[]>();
        foreach (JsonElement value in values.EnumerateArray()) {
            byte[] hash = DecodeRequiredBase64(value.GetString(), "proof hash");
            CtMerkleTree.RequireHash(hash);
            result.Add(hash);
        }
        return result;
    }

    private static CtLogDescriptor DescribeRequest(CtLogIngestionBatchRequest request) => new() {
        Url = request.LogUrl, ApiKind = request.ApiKind, MonitoringUrl = request.MonitoringUrl,
        SubmissionUrl = request.SubmissionUrl, PublicKey = request.PublicKey, LogId = request.LogId
    };
}
