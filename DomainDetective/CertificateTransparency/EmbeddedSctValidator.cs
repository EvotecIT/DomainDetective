using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;

namespace DomainDetective;

/// <summary>Parses, verifies and evaluates the embedded SCT list of a certificate.</summary>
internal static class EmbeddedSctValidator {
    internal const string ChromeLogListUrl = "https://www.gstatic.com/ct/log_list/v3/log_list.json";
    internal const string AppleLogListUrl = "https://valid.apple.com/ct/log_list/current_log_list.json";
    private static readonly DerObjectIdentifier SctListOid = new("1.3.6.1.4.1.11129.2.4.2");
    private static readonly TimeSpan LogListLifetime = TimeSpan.FromHours(6);
    private static readonly ConcurrentDictionary<string, (IReadOnlyList<CtLogDescriptor> Logs, DateTimeOffset ExpiresAtUtc)> LogLists = new(StringComparer.Ordinal);

    internal sealed class ParsedSct {
        public byte[] LogId { get; init; } = Array.Empty<byte>();
        public ulong TimestampMilliseconds { get; init; }
        public byte[] Extensions { get; init; } = Array.Empty<byte>();
        public byte HashAlgorithm { get; init; }
        public byte SignatureAlgorithm { get; init; }
        public byte[] Signature { get; init; } = Array.Empty<byte>();
        public DateTimeOffset Timestamp => DateTimeOffset.FromUnixTimeMilliseconds((long)TimestampMilliseconds);
    }

    /// <summary>Loads a log list through <see cref="CtLogIngestionClient"/> and keeps it for a few hours; returns null when unavailable.</summary>
    internal static async Task<IReadOnlyList<CtLogDescriptor>?> GetLogListAsync(string url, TimeSpan timeout, CancellationToken cancellationToken) {
        if (LogLists.TryGetValue(url, out var cached) && cached.ExpiresAtUtc > DateTimeOffset.UtcNow) return cached.Logs;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (timeout > TimeSpan.Zero && timeout != Timeout.InfiniteTimeSpan) deadline.CancelAfter(timeout);
        try {
            var logs = await new CtLogIngestionClient().GetLogsAsync(url, includeRetired: true, includePending: true,
                includeUnknownState: true, cancellationToken: deadline.Token).ConfigureAwait(false);
            if (logs.Count == 0) return null;
            LogLists[url] = (logs, DateTimeOffset.UtcNow.Add(LogListLifetime));
            return logs;
        } catch (Exception) when (!cancellationToken.IsCancellationRequested) {
            return null;
        }
    }

    internal static EmbeddedSctValidation? Validate(BcCertificate leaf, BcCertificate? issuer,
        IReadOnlyList<CtLogDescriptor>? chromeLogs, IReadOnlyList<CtLogDescriptor>? appleLogs) {
        Asn1OctetString? extension = leaf.GetExtensionValue(SctListOid);
        if (extension == null) return null;
        IReadOnlyList<ParsedSct> parsed;
        try {
            parsed = Parse(extension.GetOctets());
        } catch (FormatException ex) {
            var rejected = new CtPolicyEvaluation { Compliance = CtPolicyCompliance.NotCompliant, Reason = "The embedded SCT list is malformed." };
            return new EmbeddedSctValidation { ParseError = ex.Message, Chrome = rejected, Apple = rejected };
        }

        Dictionary<string, CtLogDescriptor> chrome = IndexLogs(chromeLogs), apple = IndexLogs(appleLogs);
        byte[]? issuerKeyHash = issuer == null ? null : Sha256(issuer.CertificateStructure.TbsCertificate.SubjectPublicKeyInfo.GetDerEncoded());
        byte[]? tbs = issuer == null ? null : CtCertificateDer.NormalizePrecertificateTbs(leaf, null);
        var scts = new List<EmbeddedSct>(parsed.Count);
        foreach (ParsedSct sct in parsed) {
            string logId = Convert.ToBase64String(sct.LogId);
            chrome.TryGetValue(logId, out CtLogDescriptor? chromeLog);
            apple.TryGetValue(logId, out CtLogDescriptor? appleLog);
            CtLogDescriptor? log = chromeLog ?? appleLog;
            scts.Add(new EmbeddedSct {
                LogId = logId,
                Timestamp = sct.Timestamp,
                HasValidLeafIndex = HasValidLeafIndex(sct.Extensions),
                LogKnown = log != null,
                LogDescription = log?.Description,
                LogOperator = log?.OperatorName,
                ChromeLogState = chromeLog == null ? null : chromeLog.State ?? string.Empty,
                AppleLogState = appleLog == null ? null : appleLog.State ?? string.Empty,
                SignatureStatus = VerifySignature(sct, log?.PublicKey, issuerKeyHash, tbs)
            });
        }

        DateTime notBefore = leaf.NotBefore.ToUniversalTime(), notAfter = leaf.NotAfter.ToUniversalTime();
        return new EmbeddedSctValidation {
            Scts = scts,
            Chrome = Evaluate(scts, chromeLogs == null ? null : chrome, "Chrome", (candidates, logs) => EvaluateChrome(candidates, logs, notBefore, notAfter)),
            Apple = Evaluate(scts, appleLogs == null ? null : apple, "Apple", (candidates, logs) => EvaluateApple(candidates, logs, notBefore, notAfter))
        };
    }

    /// <summary>Decodes the extension value per RFC 6962 section 3.3: a DER OCTET STRING holding a TLS SignedCertificateTimestampList.</summary>
    internal static IReadOnlyList<ParsedSct> Parse(byte[] extensionValue) {
        byte[] list;
        try {
            Asn1OctetString? wrapper = Asn1OctetString.GetInstance(Asn1Object.FromByteArray(extensionValue));
            if (wrapper == null || !extensionValue.SequenceEqual(wrapper.GetDerEncoded())) {
                throw new FormatException("SCT list extension is not a DER OCTET STRING.");
            }
            list = wrapper.GetOctets();
        } catch (Exception ex) when (ex is IOException or ArgumentException or InvalidCastException) {
            throw new FormatException("SCT list extension is not a DER OCTET STRING.", ex);
        }

        int offset = 0;
        byte[] body = ReadVector(list, ref offset, 2, "SCT list");
        if (offset != list.Length) throw new FormatException("SCT list has trailing bytes.");
        if (body.Length == 0) throw new FormatException("SCT list is empty.");
        var output = new List<ParsedSct>();
        int position = 0;
        while (position < body.Length) {
            byte[] serialized = ReadVector(body, ref position, 2, "serialized SCT");
            if (serialized.Length == 0) throw new FormatException("Serialized SCT is empty.");
            int cursor = 0;
            byte version = ReadBytes(serialized, ref cursor, 1, "SCT version")[0];
            if (version != 0) throw new FormatException($"SCT version {version} is not v1.");
            byte[] logId = ReadBytes(serialized, ref cursor, 32, "SCT log ID");
            ulong timestamp = 0;
            foreach (byte b in ReadBytes(serialized, ref cursor, 8, "SCT timestamp")) timestamp = (timestamp << 8) | b;
            if (timestamp > 253402300799999UL) throw new FormatException("SCT timestamp is out of range.");
            byte[] extensions = ReadVector(serialized, ref cursor, 2, "SCT extensions");
            byte[] algorithms = ReadBytes(serialized, ref cursor, 2, "SCT signature algorithm");
            byte[] signature = ReadVector(serialized, ref cursor, 2, "SCT signature");
            if (cursor != serialized.Length) throw new FormatException("Serialized SCT has trailing bytes.");
            output.Add(new ParsedSct {
                LogId = logId, TimestampMilliseconds = timestamp, Extensions = extensions,
                HashAlgorithm = algorithms[0], SignatureAlgorithm = algorithms[1], Signature = signature
            });
        }
        return output;
    }

    private static SctSignatureStatus VerifySignature(ParsedSct sct, string? logKey, byte[]? issuerKeyHash, byte[]? tbs) {
        if (logKey == null || issuerKeyHash == null || tbs == null) return SctSignatureStatus.Unverified;
        AsymmetricKeyParameter key;
        try {
            key = PublicKeyFactory.CreateKey(Convert.FromBase64String(logKey));
        } catch (Exception) {
            return SctSignatureStatus.Unverified;
        }
        // RFC 6962 section 2.1.4: SHA-256 (4) with RSA (1) or ECDSA (3).
        if (sct.HashAlgorithm != 4 || (sct.SignatureAlgorithm != 1 && sct.SignatureAlgorithm != 3)) return SctSignatureStatus.Invalid;
        using var signed = new MemoryStream();
        signed.WriteByte(0); // sct_version v1
        signed.WriteByte(0); // signature_type certificate_timestamp
        for (int shift = 56; shift >= 0; shift -= 8) signed.WriteByte((byte)(sct.TimestampMilliseconds >> shift));
        signed.WriteByte(0); signed.WriteByte(1); // entry_type precert_entry
        signed.Write(issuerKeyHash, 0, issuerKeyHash.Length);
        signed.WriteByte((byte)(tbs.Length >> 16)); signed.WriteByte((byte)(tbs.Length >> 8)); signed.WriteByte((byte)tbs.Length);
        signed.Write(tbs, 0, tbs.Length);
        signed.WriteByte((byte)(sct.Extensions.Length >> 8)); signed.WriteByte((byte)sct.Extensions.Length);
        signed.Write(sct.Extensions, 0, sct.Extensions.Length);
        byte[] message = signed.ToArray();
        try {
            ISigner verifier = SignerUtilities.GetSigner(sct.SignatureAlgorithm == 1 ? "SHA256withRSA" : "SHA256withECDSA");
            verifier.Init(false, key);
            verifier.BlockUpdate(message, 0, message.Length);
            return verifier.VerifySignature(sct.Signature) ? SctSignatureStatus.Valid : SctSignatureStatus.Invalid;
        } catch (Exception) {
            return SctSignatureStatus.Invalid;
        }
    }

    private static CtPolicyEvaluation Evaluate(IReadOnlyList<EmbeddedSct> scts, Dictionary<string, CtLogDescriptor>? logs, string browser,
        Func<IReadOnlyList<EmbeddedSct>, Dictionary<string, CtLogDescriptor>, CtPolicyEvaluation> policy) {
        if (logs == null) return new CtPolicyEvaluation { Reason = $"The {browser} CT log list was unavailable." };
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var eligible = scts.Where(sct => sct.Timestamp <= now).ToList();
        CtPolicyEvaluation strict = policy(eligible.Where(static sct => sct.SignatureStatus == SctSignatureStatus.Valid).ToList(), logs);
        if (strict.Compliance == CtPolicyCompliance.Compliant) return strict;
        CtPolicyEvaluation optimistic = policy(eligible.Where(static sct => sct.SignatureStatus != SctSignatureStatus.Invalid).ToList(), logs);
        return optimistic.Compliance == CtPolicyCompliance.Compliant
            ? new CtPolicyEvaluation { Reason = "Compliance depends on SCT signatures that could not be verified." }
            : optimistic;
    }

    internal static CtPolicyEvaluation EvaluateChrome(IReadOnlyList<EmbeddedSct> candidates,
        Dictionary<string, CtLogDescriptor> logs, DateTime notBefore, DateTime notAfter) {
        // Chrome CT policy (googlechrome.github.io/CertificateTransparency/ct_policy.html): one SCT from a Qualified/Usable/ReadOnly log;
        // SCTs from 2 (lifetime <= 180 days) or 3 distinct Qualified/Usable/ReadOnly/Retired logs; at least 2 distinct operators;
        // A retired log's SCT and the earliest candidate SCT from a non-retired log must both predate retirement.
        candidates = candidates.Where(sct => !logs.TryGetValue(sct.LogId, out CtLogDescriptor? log) ||
            log.ApiKind != CtLogApiKind.StaticCt || sct.HasValidLeafIndex).ToList();
        DateTimeOffset earliest = candidates
            .Where(sct => logs.TryGetValue(sct.LogId, out CtLogDescriptor? log) && !log.IsRetired)
            .Select(static sct => sct.Timestamp).DefaultIfEmpty(DateTimeOffset.MaxValue).Min();
        var counted = candidates
            .Select(sct => (Sct: sct, Log: logs.TryGetValue(sct.LogId, out CtLogDescriptor? log) ? log : null))
            .Where(item => item.Log != null && (IsCurrentlyApproved(item.Log) ||
                (item.Log.IsRetired && earliest < item.Log.StateTimestampUtc && item.Sct.Timestamp < item.Log.StateTimestampUtc)))
            .ToList();
        if (!counted.Any(static item => IsCurrentlyApproved(item.Log!))) return NotCompliant("No embedded SCT comes from a qualified, usable or read-only log.");
        int required = notAfter - notBefore <= TimeSpan.FromDays(180) ? 2 : 3;
        int distinctLogs = counted.Select(static item => item.Log!.LogId).Distinct(StringComparer.Ordinal).Count();
        if (distinctLogs < required) return NotCompliant($"Embedded SCTs come from {distinctLogs} eligible distinct logs; {required} are required.");
        int operators = counted.Select(static item => OperatorAt(item.Log!, item.Sct.Timestamp)).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        if (operators < 2) return NotCompliant("Eligible embedded SCTs come from fewer than 2 distinct log operators.");
        return new CtPolicyEvaluation {
            Compliance = CtPolicyCompliance.Compliant,
            Reason = $"Embedded SCTs from {distinctLogs} eligible logs and {operators} operators; {required} logs required."
        };
    }

    internal static CtPolicyEvaluation EvaluateApple(IReadOnlyList<EmbeddedSct> candidates, Dictionary<string, CtLogDescriptor> logs,
        DateTime notBefore, DateTime notAfter) {
        // Apple CT policy v1.1 (apple/apple-root-program, 2026-11-05): lifetime counts notBefore..notAfter inclusive in 86,400-second days;
        // <= 180 days needs SCTs from 2 distinct logs with at most 1 per operator counted, 181-398 days needs 3 with at most 2 per operator;
        // one SCT from a currently approved (qualified/usable/readonly) log; others may come from a log retired after the SCT.
        long lifetimeDays = (long)Math.Ceiling(((notAfter - notBefore).TotalSeconds + 1) / 86400d);
        if (lifetimeDays > 398) return NotCompliant($"Certificate lifetime of {lifetimeDays} days exceeds Apple's 398-day limit.");
        (int required, int perOperator) = lifetimeDays <= 180 ? (2, 1) : (3, 2);
        var counted = candidates
            .Select(sct => (Sct: sct, Log: logs.TryGetValue(sct.LogId, out CtLogDescriptor? log) ? log : null))
            .Where(static item => item.Log != null &&
                (IsCurrentlyApproved(item.Log) || (item.Log.IsRetired && item.Sct.Timestamp < item.Log.StateTimestampUtc)))
            .Select(static item => item.Log!)
            .GroupBy(static log => log.LogId, StringComparer.Ordinal).Select(static group => group.First())
            .GroupBy(static log => log.OperatorName, StringComparer.OrdinalIgnoreCase)
            .SelectMany(group => group
                .OrderByDescending(IsCurrentlyApproved)
                .Take(perOperator))
            .ToList();
        if (!counted.Any(IsCurrentlyApproved)) return NotCompliant("No embedded SCT comes from a currently approved log.");
        if (counted.Count < required) {
            return NotCompliant($"Embedded SCTs count for {counted.Count} distinct logs after the per-operator limit of {perOperator}; {required} are required.");
        }
        return new CtPolicyEvaluation {
            Compliance = CtPolicyCompliance.Compliant,
            Reason = $"Embedded SCTs count for {counted.Count} distinct logs; {required} required for a {lifetimeDays}-day certificate."
        };
    }

    private static bool HasValidLeafIndex(byte[] extensions) {
        bool found = false;
        for (int offset = 0; offset < extensions.Length;) {
            if (extensions.Length - offset < 3) return false;
            byte type = extensions[offset++];
            int length = (extensions[offset++] << 8) | extensions[offset++];
            if (length > extensions.Length - offset) return false;
            if (type == 0) {
                if (found || length < 5) return false;
                found = true;
            }
            offset += length;
        }
        return found;
    }

    private static string? OperatorAt(CtLogDescriptor log, DateTimeOffset timestamp) {
        foreach (var previous in log.PreviousOperators) {
            if (timestamp < previous.EndTimeUtc) return previous.Name;
        }
        return log.OperatorName;
    }

    private static bool IsCurrentlyApproved(CtLogDescriptor log) => log.IsQualified || log.IsUsable || log.IsReadOnly;

    private static CtPolicyEvaluation NotCompliant(string reason) => new() { Compliance = CtPolicyCompliance.NotCompliant, Reason = reason };

    private static Dictionary<string, CtLogDescriptor> IndexLogs(IReadOnlyList<CtLogDescriptor>? logs) {
        var index = new Dictionary<string, CtLogDescriptor>(StringComparer.Ordinal);
        if (logs == null) return index;
        foreach (CtLogDescriptor log in logs) {
            if (!string.IsNullOrEmpty(log.LogId)) index[log.LogId!] = log;
        }
        return index;
    }

    private static byte[] Sha256(byte[] data) {
        using var sha = SHA256.Create();
        return sha.ComputeHash(data);
    }

    private static byte[] ReadVector(byte[] data, ref int offset, int lengthBytes, string field) {
        int length = 0;
        foreach (byte b in ReadBytes(data, ref offset, lengthBytes, field + " length")) length = (length << 8) | b;
        return ReadBytes(data, ref offset, length, field);
    }

    private static byte[] ReadBytes(byte[] data, ref int offset, int count, string field) {
        if (count > data.Length - offset) throw new FormatException($"{field} is truncated.");
        byte[] value = new byte[count];
        Buffer.BlockCopy(data, offset, value, 0, count);
        offset += count;
        return value;
    }
}
