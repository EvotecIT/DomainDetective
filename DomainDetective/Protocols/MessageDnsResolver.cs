using DnsClientX;
using MimeKit.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>Bounded, operation-local DNS evidence; MimeKit owns cryptographic record interpretation.</summary>
internal sealed class MessageDnsResolver : IDnsResolver {
    private readonly MessageVerificationOptions options;
    private readonly DnsConfiguration dns;
    private readonly Dictionary<string, DnsTxtResponse> records = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> dnsKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> failures = new(StringComparer.OrdinalIgnoreCase);
    private int queries;
    internal List<string> Failures { get; } = new();
    internal bool UsedDns { get; private set; }
    internal void BeginVerification() => UsedDns = false;
    internal IReadOnlyList<string>? CachedRecords(string domain) =>
        records.TryGetValue(DkimDnsName.NormalizeRecordName(domain), out var response) && response.Status == DnsQueryStatus.Success
            ? response.Records : null;

    internal MessageDnsResolver(MessageVerificationOptions options, DnsConfiguration dns) {
        this.options = options;
        this.dns = dns;
        foreach (var pair in options.PublicKeyRecords) {
            records[DkimDnsName.NormalizeRecordName(pair.Key)] = new DnsTxtResponse(new[] { pair.Value });
        }
    }

    public DnsTxtResponse QueryTxt(string domain, CancellationToken cancellationToken = default) =>
        QueryTxtAsync(domain, cancellationToken).GetAwaiter().GetResult();

    public async Task<DnsTxtResponse> QueryTxtAsync(string domain, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        var host = DkimDnsName.NormalizeRecordName(domain);
        if (dnsKeys.Contains(host)) UsedDns = true;
        if (failures.TryGetValue(host, out var failure)) Failures.Add(failure);
        if (records.TryGetValue(host, out var cached)) return cached;
        if (!options.AllowDnsLookups) return Unavailable(host, "DNS evidence unavailable offline for " + host + ".");
        if (queries >= options.MaximumDnsQueries) return Unavailable(host, "Message verification DNS query limit reached.");
        queries++;
        UsedDns = true;
        dnsKeys.Add(host);
        try {
            var response = await dns.QueryDNSResponse(host, DnsRecordType.TXT, cancellationToken: cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            DnsTxtResponse result;
            if (!string.IsNullOrEmpty(response.Error) || response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) {
                return Unavailable(host, "DNS query could not complete for " + host + ".");
            }
            if (response.Status == DnsResponseCode.NXDomain) {
                result = new DnsTxtResponse(DnsQueryStatus.NonExistentDomain);
            } else {
                result = new DnsTxtResponse((response.Answers ?? Array.Empty<DnsAnswer>())
                    .Where(answer => answer.Type == DnsRecordType.TXT).Select(answer => answer.TxtConcatenatedData));
            }
            records[host] = result;
            return result;
        } catch (OperationCanceledException) { throw; }
        catch (Exception ex) {
            return Unavailable(host, "DNS query could not complete for " + host + ": " + ex.Message);
        }
    }

    private DnsTxtResponse Unavailable(string host, string reason) {
        Failures.Add(reason);
        failures[host] = reason;
        return records[host] = new DnsTxtResponse(DnsQueryStatus.TemporaryFailure);
    }
}
