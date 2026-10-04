using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public sealed partial class CtLogIngestionClient {
    private async Task VerifyRfcRangeAsync(string logUrl, long start, IReadOnlyList<RawCtEntryPayload> payloads,
        CtSignedTreeHead head, TimeSpan timeout, CancellationToken cancellationToken) {
        if (payloads.Count == 0) return;
        var leaves = new List<byte[]>(payloads.Count);
        for (int i = 0; i < payloads.Count; i++) {
            try { leaves.Add(CtMerkleTree.HashLeaf(DecodeRequiredBase64(payloads[i].LeafInputBase64, "entry leaf"))); }
            catch (InvalidOperationException ex) { throw new CtEntryDecodingException(logUrl, start + i, payloads[i], ex.Message, ex); }
        }
        var outsideHashes = new Dictionary<(long Start, long Size), byte[]>();
        await AddBoundaryProofAsync(start, leaves[0]).ConfigureAwait(false);
        if (payloads.Count > 1) await AddBoundaryProofAsync(start + payloads.Count - 1, leaves[leaves.Count - 1]).ConfigureAwait(false);
        byte[] computed = await CtMerkleTree.ComputeRangeRootAsync(head.TreeSize, start, leaves, (rangeStart, size) => {
            if (!outsideHashes.TryGetValue((rangeStart, size), out byte[]? hash))
                throw new InvalidOperationException("CT range proof is missing an outside subtree.");
            return Task.FromResult(hash);
        }, cancellationToken).ConfigureAwait(false);
        if (!CtMerkleTree.Equal(computed, DecodeRequiredBase64(head.RootHashBase64, "verified root")))
            throw new InvalidOperationException("Fetched CT entry range does not match the signed Merkle root.");

        async Task AddBoundaryProofAsync(long index, byte[] expectedLeafHash) {
            string json = await FetchJsonAsync(CombineLogUrl(logUrl, $"ct/v1/get-entry-and-proof?leaf_index={index}&tree_size={head.TreeSize}"), timeout, cancellationToken).ConfigureAwait(false);
            using var document = JsonDocument.Parse(json);
            byte[] proofLeaf = DecodeRequiredBase64(GetString(document.RootElement, "leaf_input"), "audit leaf");
            if (!CtMerkleTree.Equal(CtMerkleTree.HashLeaf(proofLeaf), expectedLeafHash))
                throw new InvalidOperationException("CT proof leaf does not match the fetched boundary entry.");
            CtMerkleTree.AddAuditPath(outsideHashes, index, head.TreeSize, ParseProof(document.RootElement, "audit_path"));
        }
    }

    private async Task VerifyStaticRangeAsync(string monitoringUrl, long start, IReadOnlyList<byte[]> leafHashes,
        CtSignedTreeHead head, TimeSpan timeout, CancellationToken cancellationToken) {
        if (leafHashes.Count == 0) return;
        var tiles = new Dictionary<string, byte[]>();
        byte[] computed = await CtMerkleTree.ComputeRangeRootAsync(head.TreeSize, start, leafHashes,
            (rangeStart, size) => GetStaticSubtreeHashAsync(monitoringUrl, rangeStart, size, head.TreeSize, tiles, timeout, cancellationToken),
            cancellationToken).ConfigureAwait(false);
        if (!CtMerkleTree.Equal(computed, DecodeRequiredBase64(head.RootHashBase64, "verified root")))
            throw new InvalidOperationException("Fetched Static CT entries do not match the signed Merkle root.");
    }

    private async Task<byte[]> GetStaticSubtreeHashAsync(string monitoringUrl, long start, long size, long treeSize,
        Dictionary<string, byte[]> tiles, TimeSpan timeout, CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();
        if (size < 1 || start < 0 || start > treeSize - size) throw new InvalidOperationException("Static CT proof subtree is outside the signed tree.");
        if ((size & (size - 1)) != 0) {
            long split = CtMerkleTree.Split(size);
            byte[] left = await GetStaticSubtreeHashAsync(monitoringUrl, start, split, treeSize, tiles, timeout, cancellationToken).ConfigureAwait(false);
            byte[] right = await GetStaticSubtreeHashAsync(monitoringUrl, start + split, size - split, treeSize, tiles, timeout, cancellationToken).ConfigureAwait(false);
            return CtMerkleTree.HashNode(left, right);
        }
        if (start % size != 0) throw new InvalidOperationException("Static CT hash subtree is not aligned.");
        int level = 0;
        long nodeSize = 1;
        while (nodeSize <= size / 256) { nodeSize *= 256; level++; }
        long nodeIndex = start / nodeSize;
        long tileIndex = nodeIndex / 256;
        int offset = checked((int)(nodeIndex % 256));
        int count = checked((int)(size / nodeSize));
        int width = checked((int)Math.Min(256, treeSize / nodeSize - tileIndex * 256));
        if (offset + count > width) throw new InvalidOperationException("Static CT hash tile does not contain the proof subtree.");
        string encodedIndex = EncodeStaticTileIndex(tileIndex);
        string path = width == 256 ? $"tile/{level}/{encodedIndex}" : $"tile/{level}/{encodedIndex}.p/{width}";
        if (!tiles.TryGetValue(path, out byte[]? tile)) {
            int expectedWidth = width;
            try { tile = await FetchBytesAsync(CombineLogUrl(monitoringUrl, path), timeout, cancellationToken).ConfigureAwait(false); }
            catch (HttpRequestException ex) when (width < 256 && IsStaticPartialTileFallbackFailure(ex)) {
                tile = await FetchBytesAsync(CombineLogUrl(monitoringUrl, $"tile/{level}/{encodedIndex}"), timeout, cancellationToken).ConfigureAwait(false);
                expectedWidth = 256;
            }
            if (tile.Length != expectedWidth * 32) throw new InvalidOperationException("Static CT hash tile has an invalid byte length.");
            tiles[path] = tile;
        }
        var hashes = new List<byte[]>(count);
        for (int i = 0; i < count; i++) {
            byte[] hash = new byte[32];
            Buffer.BlockCopy(tile, (offset + i) * 32, hash, 0, 32);
            hashes.Add(hash);
        }
        while (hashes.Count > 1) {
            var parents = new List<byte[]>(hashes.Count / 2);
            for (int i = 0; i < hashes.Count; i += 2) parents.Add(CtMerkleTree.HashNode(hashes[i], hashes[i + 1]));
            hashes = parents;
        }
        return hashes[0];
    }

    private async Task BuildStaticConsistencyProofAsync(string monitoringUrl, long firstSize, long secondSize, long start,
        bool complete, long treeSize, List<byte[]> proof, Dictionary<string, byte[]> tiles, TimeSpan timeout, CancellationToken cancellationToken) {
        if (firstSize == secondSize) {
            if (!complete) proof.Add(await GetStaticSubtreeHashAsync(monitoringUrl, start, secondSize, treeSize, tiles, timeout, cancellationToken).ConfigureAwait(false));
            return;
        }
        long split = CtMerkleTree.Split(secondSize);
        if (firstSize <= split) {
            await BuildStaticConsistencyProofAsync(monitoringUrl, firstSize, split, start, complete, treeSize, proof, tiles, timeout, cancellationToken).ConfigureAwait(false);
            proof.Add(await GetStaticSubtreeHashAsync(monitoringUrl, start + split, secondSize - split, treeSize, tiles, timeout, cancellationToken).ConfigureAwait(false));
        } else {
            await BuildStaticConsistencyProofAsync(monitoringUrl, firstSize - split, secondSize - split, start + split, false, treeSize, proof, tiles, timeout, cancellationToken).ConfigureAwait(false);
            proof.Add(await GetStaticSubtreeHashAsync(monitoringUrl, start, split, treeSize, tiles, timeout, cancellationToken).ConfigureAwait(false));
        }
    }
}
