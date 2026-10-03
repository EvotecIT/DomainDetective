using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DmarcAnalysis {
    /// <summary>Whether an auxiliary reporting destination or authorization query failed.</summary>
    public bool ReportingQueryFailed { get; private set; }
    /// <summary>Latest reporting query failure; the discovered policy remains available.</summary>
    public string? ReportingQueryError { get; private set; }

    private async Task CheckReportingAuthorizationAsync(string? authorDomain, Func<string, string>? getOrgDomain,
        Func<string, CancellationToken, Task<string>>? getOrgDomainAsync, InternalLogger? logger, CancellationToken token) {
        var domains = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        void Add(string domain, string address) {
            if (!domains.TryGetValue(domain, out var addresses)) domains.Add(domain, addresses = new List<string>());
            addresses.Add(address);
        }
        foreach (string mailbox in MailtoRua.Concat(MailtoRuf)) {
            int at = mailbox.LastIndexOf('@');
            if (at >= 0 && at < mailbox.Length - 1) Add(mailbox.Substring(at + 1), mailbox);
        }
        foreach (string url in HttpRua.Concat(HttpRuf)) {
            if (Uri.TryCreate(url, UriKind.Absolute, out var uri)) Add(uri.Host, url);
        }
        string? policyDomain = PolicyDomain ?? authorDomain;
        if (policyDomain == null) return;
        bool hasResolver = getOrgDomain != null || getOrgDomainAsync != null;
        Task<string> Resolve(string target) => getOrgDomainAsync != null ? getOrgDomainAsync(target, token)
            : Task.FromResult(getOrgDomain?.Invoke(target) ?? target);
        foreach (var report in domains) {
            string destination = report.Key;
            if (destination.Equals(policyDomain, StringComparison.OrdinalIgnoreCase)) continue;
            try {
                if (hasResolver) {
                    string policyOrg = await Resolve(policyDomain).ConfigureAwait(false);
                    string destinationOrg = await Resolve(destination).ConfigureAwait(false);
                    if (authorDomain == policyDomain && getOrgDomainAsync != null) OrganizationalDomain = policyOrg;
                    if (!string.IsNullOrWhiteSpace(policyOrg) && policyOrg.Equals(destinationOrg, StringComparison.OrdinalIgnoreCase)) continue;
                    logger?.WriteWarningCode(DmarcCodes.AlignmentMismatch, "Report address {0} is not aligned with {1}.", string.Join(", ", report.Value), policyDomain);
                }
                string name = $"{policyDomain}._report._dmarc.{destination}";
                var answers = await QueryDns(name, DnsRecordType.TXT, token).ConfigureAwait(false);
                ExternalReportAuthorization[destination] = answers.Any(answer => answer.Type == DnsRecordType.TXT
                    && IsDmarcReportAuthorizationRecord(answer.TxtConcatenatedData));
            } catch (OperationCanceledException) when (token.IsCancellationRequested) {
                throw;
            } catch (Exception ex) when (ex is DnsQueryFailureException || ex is TimeoutException || ex is System.Net.Http.HttpRequestException || ex is TaskCanceledException) {
                ReportingQueryFailed = true;
                ReportingQueryError = ex.Message;
                logger?.WriteWarningCode(DmarcCodes.ReportingQueryFailed, "DMARC reporting query failed for {0}: {1}", destination, ex.Message);
            }
        }
    }
}
