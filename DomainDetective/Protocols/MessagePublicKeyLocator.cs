using DnsClientX;
using MimeKit.Cryptography;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Text.RegularExpressions;

namespace DomainDetective;

/// <summary>Per-operation key acquisition, bounded and offline unless explicitly enabled.</summary>
internal sealed class MessagePublicKeyLocator : DkimPublicKeyLocatorBase {
    private readonly MessageVerificationOptions _options;
    private readonly DnsConfiguration _dns;
    private readonly Dictionary<string, string> _records = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _dnsKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _failedKeys = new(StringComparer.OrdinalIgnoreCase);
    private int _queries;
    internal List<string> Failures { get; } = new();
    internal bool UsedDns { get; private set; }
    internal void BeginVerification() { UsedDns = false; }

    internal MessagePublicKeyLocator(MessageVerificationOptions options, DnsConfiguration dns) {
        _options = options;
        _dns = dns;
        foreach (var pair in options.PublicKeyRecords) { _records[pair.Key.Trim().TrimEnd('.')] = pair.Value; }
    }

    public override AsymmetricKeyParameter LocatePublicKey(string methods, string domain, string selector, CancellationToken cancellationToken = default) {
        return LocatePublicKeyAsync(methods, domain, selector, cancellationToken).GetAwaiter().GetResult();
    }

    public override async Task<AsymmetricKeyParameter> LocatePublicKeyAsync(string methods, string domain, string selector, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        var normalizedDomain = Helpers.DomainHelper.ValidateIdn(domain);
        if (string.IsNullOrWhiteSpace(selector) || selector.Length > 253 || !Regex.IsMatch(selector, @"^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1))
            || selector.Split('.').Any(label => label.Length > 63)) {
            throw new ArgumentException("Invalid DKIM selector.", nameof(selector));
        }
        var host = selector.ToLowerInvariant() + "._domainkey." + normalizedDomain.ToLowerInvariant();
        if (host.Length > 253) { throw new ArgumentException("DKIM key lookup name exceeds DNS limits.", nameof(selector)); }
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
                var candidates = answers.Select(answer => answer.Data).Where(value => MessageHeaderValueParser.ParseTags(value).ContainsKey("p")).Distinct(StringComparer.Ordinal).ToArray();
                if (candidates.Length != 1) { throw new InvalidOperationException("Exactly one DKIM public-key record is required for " + host + "."); }
                record = candidates[0];
                _records[host] = record;
            }
            return GetPublicKey(record);
        } catch (OperationCanceledException) { throw; }
        catch (Exception ex) {
            if (cacheKeyFailure && !_failedKeys.ContainsKey(host)) { _failedKeys[host] = ex.Message; }
            Failures.Add(ex.Message);
            throw new InvalidOperationException("Public-key acquisition failed for " + host + ": " + ex.Message, ex);
        }
    }
}
