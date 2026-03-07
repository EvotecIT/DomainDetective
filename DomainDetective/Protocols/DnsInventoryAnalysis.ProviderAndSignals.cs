using DnsClientX;
using DomainDetective.Helpers;
using DomainDetective.Providers.Dns;
using DomainDetective.Providers.Email;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public sealed partial class DnsInventoryAnalysis : IHasAssessments
{
    private void TryDetectProvider(List<DnsInventoryQuery> queries)
    {
        try
        {
            if (queries == null || queries.Count == 0)
            {
                return;
            }

            var nsHosts = new List<string>();
            foreach (var q in queries)
            {
                if (q.RecordType != DnsRecordType.NS)
                {
                    continue;
                }

                foreach (var r in q.Records)
                {
                    if (r.Section != DnsInventorySection.Answer || r.Type != DnsRecordType.NS)
                    {
                        continue;
                    }

                    var host = NormalizeHost(r.Data);
                    if (!string.IsNullOrWhiteSpace(host))
                    {
                        nsHosts.Add(host);
                    }
                }
            }

            string? soaPrimary = null;
            foreach (var q in queries)
            {
                foreach (var r in q.Records)
                {
                    if (r.Type != DnsRecordType.SOA)
                    {
                        continue;
                    }

                    var mname = TryParseSoaPrimaryNameServer(r.Data);
                    if (!string.IsNullOrWhiteSpace(mname))
                    {
                        soaPrimary = mname;
                        break;
                    }
                }
                if (!string.IsNullOrWhiteSpace(soaPrimary))
                {
                    break;
                }
            }

            var match = DnsProviderDetector.Detect(nsHosts, soaPrimary);
            Provider = match.Provider;
            ProviderScore = match.Score;
            ProviderEvidence = match.Evidence;
        }
        catch
        {
        }
    }

    private void TryDetectMailProvider(List<DnsInventoryQuery> queries)
    {
        try
        {
            if (queries == null || queries.Count == 0)
            {
                return;
            }

            var mxHosts = new List<string>();
            foreach (var q in queries)
            {
                if (q.RecordType != DnsRecordType.MX)
                {
                    continue;
                }

                foreach (var r in q.Records)
                {
                    if (r.Section != DnsInventorySection.Answer || r.Type != DnsRecordType.MX)
                    {
                        continue;
                    }

                    var host = TryParseMxHost(r.Data);
                    if (!string.IsNullOrWhiteSpace(host))
                    {
                        mxHosts.Add(host);
                    }
                }
            }

            var match = MailProviderKindDetector.DetectFromMxHosts(mxHosts);
            MailProvider = match.Provider;
            MailProviderScore = match.Score;
            MailProviderEvidence = match.Evidence;
        }
        catch
        {
        }
    }

    private void TryDetectCnameTarget(List<DnsInventoryQuery> queries)
    {
        try
        {
            if (queries == null || queries.Count == 0)
            {
                return;
            }

            var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var q in queries)
            {
                if (q.RecordType != DnsRecordType.CNAME)
                {
                    continue;
                }

                foreach (var r in q.Records)
                {
                    if (r.Section != DnsInventorySection.Answer || r.Type != DnsRecordType.CNAME)
                    {
                        continue;
                    }

                    var t = NormalizeHost(r.Data);
                    if (!string.IsNullOrWhiteSpace(t))
                    {
                        targets.Add(t);
                    }
                }
            }

            if (targets.Count == 0)
            {
                return;
            }

            var evidence = new List<string>();
            var bestProvider = DnsCnameTargetProvider.Unknown;
            var flags = DnsCnameTargetFlags.None;

            foreach (var target in targets.OrderBy(t => t, StringComparer.OrdinalIgnoreCase))
            {
                if (evidence.Count < 10)
                {
                    evidence.Add($"Apex CNAME: {target}");
                }

                var m = DnsCnameTargetDetector.Detect(target);
                flags |= m.Flags;

                if (bestProvider == DnsCnameTargetProvider.Unknown && m.Provider != DnsCnameTargetProvider.Unknown)
                {
                    bestProvider = m.Provider;
                }

                foreach (var e in m.Evidence)
                {
                    if (evidence.Count >= 10)
                    {
                        break;
                    }

                    if (!string.IsNullOrWhiteSpace(e))
                    {
                        evidence.Add(e);
                    }
                }
            }

            CnameTargetProvider = bestProvider;
            CnameTargetFlags = flags;
            CnameTargetEvidence = evidence;
        }
        catch
        {
        }
    }

    private void TryDetectTxtSignals(List<DnsInventoryQuery> queries)
    {
        try
        {
            if (queries == null || queries.Count == 0)
            {
                return;
            }

            var txt = new List<string>();
            foreach (var q in queries)
            {
                if (q.RecordType != DnsRecordType.TXT)
                {
                    continue;
                }

                foreach (var r in q.Records)
                {
                    if (r.Section != DnsInventorySection.Answer || r.Type != DnsRecordType.TXT)
                    {
                        continue;
                    }

                    if (!string.IsNullOrWhiteSpace(r.Data))
                    {
                        txt.Add(r.Data);
                    }
                }
            }

            var match = DnsTxtSignalDetector.Detect(txt);
            TxtSignals = match.Signals;
            TxtSignalsEvidence = match.Evidence;
        }
        catch
        {
        }
    }

    private void TryDetectTxtSignalsExposure()
    {
        try
        {
            if (string.IsNullOrWhiteSpace(Subject))
            {
                return;
            }

            var signals = TxtSignals & ~DnsTxtSignals.Spf;
            if (signals == DnsTxtSignals.None)
            {
                return;
            }

            var evidence = (TxtSignalsEvidence ?? Array.Empty<string>())
                .Where(e => !string.IsNullOrWhiteSpace(e))
                .Where(e => e.IndexOf("spf", StringComparison.OrdinalIgnoreCase) < 0)
                .Take(4)
                .ToList();

            var msg = evidence.Count > 0
                ? $"Third-party TXT verification/service tokens present: {string.Join("; ", evidence)}"
                : "Third-party TXT verification/service tokens present.";

            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Category = "DNS Inventory",
                Code = DnsInventoryCodes.TxtSignalsExposed,
                Target = Subject,
                Message = msg
            });
        }
        catch
        {
        }
    }

    private void TryDetectCaaIssuers(List<DnsInventoryQuery> queries)
    {
        try
        {
            if (queries == null || queries.Count == 0)
            {
                return;
            }

            var caa = new List<string>();
            foreach (var q in queries)
            {
                if (q.RecordType != DnsRecordType.CAA)
                {
                    continue;
                }

                foreach (var r in q.Records)
                {
                    if (r.Section != DnsInventorySection.Answer || r.Type != DnsRecordType.CAA)
                    {
                        continue;
                    }

                    if (!string.IsNullOrWhiteSpace(r.Data))
                    {
                        caa.Add(r.Data);
                    }
                }
            }

            var match = DnsCaaIssuerDetector.Detect(caa);
            CaaIssuers = match.Issuers;
            CaaIssuersEvidence = match.Evidence;
        }
        catch
        {
        }
    }

    private async Task TryDetectIpv6ReadinessAsync(List<DnsInventoryQuery> queries, CancellationToken cancellationToken)
    {
        try
        {
            if (!EvaluateIpv6Readiness || queries == null || queries.Count == 0 || string.IsNullOrWhiteSpace(Subject))
            {
                return;
            }

            var a = queries.FirstOrDefault(q => q.RecordType == DnsRecordType.A);
            var aaaa = queries.FirstOrDefault(q => q.RecordType == DnsRecordType.AAAA);
            var mx = queries.FirstOrDefault(q => q.RecordType == DnsRecordType.MX);
            var ns = queries.FirstOrDefault(q => q.RecordType == DnsRecordType.NS);

            bool apexHasA = a != null && a.Records.Any(r => r.Section == DnsInventorySection.Answer && r.Type == DnsRecordType.A);
            bool apexHasAaaa = aaaa != null && aaaa.Records.Any(r => r.Section == DnsInventorySection.Answer && r.Type == DnsRecordType.AAAA);

            var mxHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (mx != null)
            {
                foreach (var r in mx.Records)
                {
                    if (r.Section != DnsInventorySection.Answer || r.Type != DnsRecordType.MX || string.IsNullOrWhiteSpace(r.Data))
                    {
                        continue;
                    }

                    var parts = r.Data.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    var host = parts.Length > 0 ? parts[parts.Length - 1].Trim().TrimEnd('.') : string.Empty;
                    if (!string.IsNullOrWhiteSpace(host))
                    {
                        mxHosts.Add(host);
                    }
                }
            }

            var nsHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (ns != null)
            {
                foreach (var r in ns.Records)
                {
                    if (r.Section != DnsInventorySection.Answer || r.Type != DnsRecordType.NS || string.IsNullOrWhiteSpace(r.Data))
                    {
                        continue;
                    }

                    var host = r.Data.Trim().TrimEnd('.');
                    if (!string.IsNullOrWhiteSpace(host))
                    {
                        nsHosts.Add(host);
                    }
                }
            }

            bool mxAny = mxHosts.Count > 0;
            bool nsAny = nsHosts.Count > 0;

            bool mxHasIpv6 = false;
            int mxAttempted = 0;

            bool nsHasIpv6 = false;
            int nsAttempted = 0;

            int budget = MaxIpv6ReadinessHostChecks <= 0 ? 0 : MaxIpv6ReadinessHostChecks;
            if (budget > 0)
            {
                foreach (var host in mxHosts.OrderBy(h => h))
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (mxAttempted + nsAttempted >= budget)
                    {
                        break;
                    }

                    try
                    {
                        var response = await QueryResponseAsync(host, DnsRecordType.AAAA, cancellationToken).ConfigureAwait(false);
                        var res = response?.Answers ?? Array.Empty<DnsAnswer>();
                        mxAttempted++;
                        if (res.Any(a => a.Type == DnsRecordType.AAAA))
                        {
                            mxHasIpv6 = true;
                            break;
                        }
                    }
                    catch
                    {
                    }
                }

                foreach (var host in nsHosts.OrderBy(h => h))
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (mxAttempted + nsAttempted >= budget)
                    {
                        break;
                    }

                    try
                    {
                        var response = await QueryResponseAsync(host, DnsRecordType.AAAA, cancellationToken).ConfigureAwait(false);
                        var res = response?.Answers ?? Array.Empty<DnsAnswer>();
                        nsAttempted++;
                        if (res.Any(a => a.Type == DnsRecordType.AAAA))
                        {
                            nsHasIpv6 = true;
                            break;
                        }
                    }
                    catch
                    {
                    }
                }
            }

            var missing = new List<string>();
            if (apexHasA && !apexHasAaaa)
            {
                missing.Add("apex AAAA missing");
            }
            if (mxAny && mxAttempted > 0 && !mxHasIpv6)
            {
                missing.Add($"no AAAA for MX hosts (checked {mxAttempted})");
            }
            if (nsAny && nsAttempted > 0 && !nsHasIpv6)
            {
                missing.Add($"no AAAA for NS hosts (checked {nsAttempted})");
            }

            if (missing.Count == 0)
            {
                return;
            }

            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Category = "DNS Inventory",
                Code = DnsInventoryCodes.Ipv6Incomplete,
                Target = Subject,
                Message = $"Incomplete IPv6 support detected: {string.Join("; ", missing)}."
            });
        }
        catch
        {
        }
    }

    private static string NormalizeHost(string? value)
    {
        var trimmed = (value ?? string.Empty).Trim().TrimEnd('.');
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        return trimmed.ToLowerInvariant();
    }

    private static string? TryParseSoaPrimaryNameServer(string? soaData)
    {
        if (soaData == null)
        {
            return null;
        }

        var trimmed = soaData.Trim();
        if (trimmed.Length == 0)
        {
            return null;
        }

        var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
        {
            return null;
        }

        return NormalizeHost(parts[0]);
    }

    private static string TryParseMxHost(string? mxData)
    {
        if (mxData == null)
        {
            return string.Empty;
        }

        var trimmed = mxData.Trim();
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
        {
            return string.Empty;
        }

        var host = parts.Length == 1 ? parts[0] : parts[parts.Length - 1];
        return NormalizeHost(host);
    }


}
