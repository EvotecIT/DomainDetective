using DnsClientX;
using MimeKit.Cryptography;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>Per-operation key acquisition, bounded and offline unless explicitly enabled.</summary>
internal sealed class MessagePublicKeyLocator : DkimPublicKeyLocatorBase {
    private readonly MessageVerificationOptions _options;
    private readonly DnsConfiguration _dns;
    private readonly Dictionary<string, string> _records = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _dnsKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _failedKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DkimKeyRecord> _keyPolicies = new(StringComparer.OrdinalIgnoreCase);
    private string? _algorithm;
    private string? _identity;
    private int _queries;
    internal List<string> Failures { get; } = new();
    internal List<string> PolicyFailures { get; } = new();
    internal bool UsedDns { get; private set; }
    internal void BeginVerification() { UsedDns = false; _algorithm = null; _identity = null; }
    internal void BeginVerification(Dictionary<string, string>? signatureTags) {
        BeginVerification();
        _algorithm = signatureTags != null && signatureTags.TryGetValue("a", out var algorithm) ? algorithm : null;
        _identity = signatureTags != null && signatureTags.TryGetValue("i", out var identity) ? identity : null;
    }

    internal MessagePublicKeyLocator(MessageVerificationOptions options, DnsConfiguration dns) {
        _options = options;
        _dns = dns;
        foreach (var pair in options.PublicKeyRecords) { _records[DkimDnsName.NormalizeRecordName(pair.Key)] = pair.Value; }
    }

    public override AsymmetricKeyParameter LocatePublicKey(string methods, string domain, string selector, CancellationToken cancellationToken = default) {
        return LocatePublicKeyAsync(methods, domain, selector, cancellationToken).GetAwaiter().GetResult();
    }

    public override async Task<AsymmetricKeyParameter> LocatePublicKeyAsync(string methods, string domain, string selector, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        var host = DkimDnsName.Lookup(domain, selector);
        var cacheKeyFailure = false;
        try {
            if (!methods.Split(':').Contains("dns/txt", StringComparer.OrdinalIgnoreCase)) { throw new NotSupportedException("Only dns/txt key acquisition is supported."); }
            if (_dnsKeys.Contains(host)) { UsedDns = true; cacheKeyFailure = true; }
            if (_failedKeys.TryGetValue(host, out var failure)) { throw new InvalidOperationException(failure); }
            if (!_records.TryGetValue(host, out var record)) {
                if (!_options.AllowDnsLookups) { throw new InvalidOperationException("Public key unavailable offline for " + host + "."); }
                if (++_queries > _options.MaximumDnsQueries) { throw new InvalidOperationException("Public-key DNS query limit reached."); }
                UsedDns = true;
                cacheKeyFailure = true;
                _dnsKeys.Add(host);
                var answers = await _dns.QueryDNS(host, DnsRecordType.TXT, cancellationToken: cancellationToken).ConfigureAwait(false);
                var candidates = answers.Where(answer => answer.Type == DnsRecordType.TXT)
                    .Select(answer => answer.TxtConcatenatedData).ToArray();
                if (candidates.Length != 1) { throw new InvalidOperationException("Exactly one DKIM public-key record is required for " + host + "."); }
                record = candidates[0];
                _records[host] = record;
            }
            if (!_keyPolicies.TryGetValue(host, out var policy)) {
                policy = DkimKeyRecord.Parse(record);
                _keyPolicies.Add(host, policy);
            }
            policy.ValidateUse(domain, _algorithm, _identity);
            // Policy accepts RFC 6376 FWS; give the cryptographic decoder only
            // normalized key material, rather than relying on its tag parser.
            return GetPublicKey("k=" + policy.KeyType + "; p=" + policy.PublicKey);
        } catch (OperationCanceledException) { throw; }
        catch (DkimKeyPolicyException ex) { PolicyFailures.Add(ex.Message); throw; }
        catch (Exception ex) {
            if (cacheKeyFailure && !_failedKeys.ContainsKey(host)) { _failedKeys[host] = ex.Message; }
            Failures.Add(ex.Message);
            throw new InvalidOperationException("Public-key acquisition failed for " + host + ": " + ex.Message, ex);
        }
    }
}
