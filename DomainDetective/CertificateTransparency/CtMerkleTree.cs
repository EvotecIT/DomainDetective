using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>RFC6962 SHA-256 Merkle calculations shared by JSON and Static CT readers.</summary>
internal static class CtMerkleTree {
    internal static byte[] HashLeaf(byte[] leaf) {
        byte[] input = new byte[leaf.Length + 1];
        Buffer.BlockCopy(leaf, 0, input, 1, leaf.Length);
        return Hash(input);
    }

    internal static byte[] HashNode(byte[] left, byte[] right) {
        RequireHash(left);
        RequireHash(right);
        byte[] input = new byte[65];
        input[0] = 1;
        Buffer.BlockCopy(left, 0, input, 1, 32);
        Buffer.BlockCopy(right, 0, input, 33, 32);
        return Hash(input);
    }

    internal static byte[] Hash(byte[] input) {
#if NET8_0_OR_GREATER
        return SHA256.HashData(input);
#else
        using var algorithm = SHA256.Create();
        return algorithm.ComputeHash(input);
#endif
    }

    internal static void RequireHash(byte[] hash) {
        if (hash.Length != 32) throw new InvalidOperationException("CT Merkle hash must contain exactly 32 bytes.");
    }

    internal static bool Equal(byte[] left, byte[] right) {
        if (left.Length != right.Length) return false;
        int difference = 0;
        for (int i = 0; i < left.Length; i++) difference |= left[i] ^ right[i];
        return difference == 0;
    }

    internal static long Split(long size) {
        if (size <= 1) throw new ArgumentOutOfRangeException(nameof(size));
        long power = 1;
        while (power <= (size - 1) / 2) power *= 2;
        return power;
    }

    // Audit paths run from the leaf upwards. Each sibling is tied to its exact subtree range.
    internal static void AddAuditPath(Dictionary<(long Start, long Size), byte[]> hashes, long index, long treeSize, IReadOnlyList<byte[]> path) {
        if (index < 0 || index >= treeSize) throw new InvalidOperationException("CT audit leaf index is outside the signed tree.");
        int position = 0;
        Visit(0, treeSize);
        if (position != path.Count) throw new InvalidOperationException("CT audit path has excess hashes.");

        void Visit(long start, long size) {
            if (size == 1) return;
            long split = Split(size);
            (long Start, long Size) sibling;
            if (index < start + split) {
                Visit(start, split);
                sibling = (start + split, size - split);
            } else {
                Visit(start + split, size - split);
                sibling = (start, split);
            }

            if (position >= path.Count) throw new InvalidOperationException("CT audit path is incomplete.");
            byte[] hash = path[position++];
            RequireHash(hash);
            if (hashes.TryGetValue(sibling, out byte[]? existing) && !Equal(existing, hash))
                throw new InvalidOperationException("CT audit paths disagree on a subtree.");
            hashes[sibling] = hash;
        }
    }

    internal static async Task<byte[]> ComputeRangeRootAsync(long treeSize, long firstIndex, IReadOnlyList<byte[]> leafHashes,
        Func<long, long, Task<byte[]>> outsideHash, CancellationToken cancellationToken) {
        if (treeSize < 1 || firstIndex < 0 || leafHashes.Count == 0 || firstIndex > treeSize - leafHashes.Count)
            throw new InvalidOperationException("CT proof range is outside the signed tree.");
        return await Compute(0, treeSize).ConfigureAwait(false);

        async Task<byte[]> Compute(long start, long size) {
            cancellationToken.ThrowIfCancellationRequested();
            if (start + size <= firstIndex || start >= firstIndex + leafHashes.Count) {
                byte[] hash = await outsideHash(start, size).ConfigureAwait(false);
                RequireHash(hash);
                return hash;
            }
            if (size == 1) return leafHashes[checked((int)(start - firstIndex))];
            long split = Split(size);
            byte[] left = await Compute(start, split).ConfigureAwait(false);
            byte[] right = await Compute(start + split, size - split).ConfigureAwait(false);
            return HashNode(left, right);
        }
    }

    internal static void VerifyConsistency(long firstSize, long secondSize, byte[] firstRoot, byte[] secondRoot, IReadOnlyList<byte[]> proof) {
        RequireHash(firstRoot);
        RequireHash(secondRoot);
        if (firstSize < 0 || secondSize < firstSize) throw new InvalidOperationException("CT signed tree rolled back.");
        if (firstSize == 0) {
            if (!Equal(firstRoot, Hash(Array.Empty<byte>())) || proof.Count != 0)
                throw new InvalidOperationException("Invalid empty CT tree consistency proof.");
            return;
        }
        if (firstSize == secondSize) {
            if (proof.Count != 0 || !Equal(firstRoot, secondRoot)) throw new InvalidOperationException("CT root changed without tree growth.");
            return;
        }
        long first = firstSize - 1;
        long second = secondSize - 1;
        while ((first & 1) != 0) { first >>= 1; second >>= 1; }
        int position = 0;
        byte[] oldHash;
        byte[] newHash;
        if (first == 0) oldHash = newHash = firstRoot;
        else {
            if (proof.Count == 0) throw new InvalidOperationException("CT consistency proof is incomplete.");
            oldHash = newHash = proof[position++];
            RequireHash(oldHash);
        }
        while (position < proof.Count) {
            if (second == 0) throw new InvalidOperationException("CT consistency proof has excess hashes.");
            byte[] sibling = proof[position++];
            RequireHash(sibling);
            if ((first & 1) != 0 || first == second) {
                oldHash = HashNode(sibling, oldHash);
                newHash = HashNode(sibling, newHash);
                while (first != 0 && (first & 1) == 0) { first >>= 1; second >>= 1; }
            } else newHash = HashNode(newHash, sibling);
            first >>= 1;
            second >>= 1;
        }
        if (second != 0 || !Equal(firstRoot, oldHash) || !Equal(secondRoot, newHash))
            throw new InvalidOperationException("CT tree growth failed Merkle consistency verification.");
    }
}
