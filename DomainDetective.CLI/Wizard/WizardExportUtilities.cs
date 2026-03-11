using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using DomainDetective;
using DomainDetective.Reports;
using DomainDetective.Scanning;

namespace DomainDetective.CLI.Wizard;

internal static class WizardExportUtilities
{
    internal static string WriteJson(DomainHealthCheck healthCheck, string domain, string outputPath)
    {
        if (healthCheck == null)
        {
            throw new ArgumentNullException(nameof(healthCheck));
        }
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentNullException(nameof(domain));
        }
        if (string.IsNullOrWhiteSpace(outputPath))
        {
            throw new ArgumentNullException(nameof(outputPath));
        }

        var json = healthCheck.ToJson();
        ReportPathHelper.EnsureParentDirectoryExists(outputPath);
        File.WriteAllText(outputPath, json);
        return outputPath;
    }

    internal static string WriteHtml(DomainHealthCheck healthCheck, string domain, string? outputPath)
    {
        if (healthCheck == null)
        {
            throw new ArgumentNullException(nameof(healthCheck));
        }
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentNullException(nameof(domain));
        }

        var resolvedPath = ReportPathHelper.ResolveOutputPath(outputPath, null, domain, ReportFormat.Html);
        var scanResult = BuildScanResult(healthCheck, domain);
        var html = Exporters.HtmlExporter.Render(scanResult);
        ReportPathHelper.EnsureParentDirectoryExists(resolvedPath);
        File.WriteAllText(resolvedPath, html);
        return resolvedPath;
    }

    internal static DomainScanResult BuildScanResult(DomainHealthCheck healthCheck, string domain)
    {
        if (healthCheck == null)
        {
            throw new ArgumentNullException(nameof(healthCheck));
        }

        var result = new DomainScanResult
        {
            Domain = domain,
            FinishedUtc = DateTime.UtcNow
        };

        var soa = healthCheck.SOAAnalysis;
        if (!string.IsNullOrWhiteSpace(soa.PrimaryNameServer) ||
            !string.IsNullOrWhiteSpace(soa.ResponsibleMailbox) ||
            soa.SerialNumber > 0)
        {
            result.Dns.Soa = new SoaInfo
            {
                PrimaryNs = soa.PrimaryNameServer,
                RName = soa.ResponsibleMailbox,
                Serial = soa.SerialNumber > 0 ? soa.SerialNumber : null
            };
        }

        result.Dns.Ns = (healthCheck.NSAnalysis?.NsRecords ?? new List<string>())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        result.Dns.Mx = BuildMxInfos(healthCheck.MXAnalysis?.MxRecords);
        result.Dns.DnssecEnabled = healthCheck.DnsSecAnalysis?.ChainValid;
        result.Dns.ZoneTransferOpen = healthCheck.ZoneTransferAnalysis?.ServerResults?.Values.Any(value => value);

        result.Mail.SpfRecord = NullIfWhiteSpace(healthCheck.SpfAnalysis?.SpfRecord);
        result.Mail.DmarcRecord = NullIfWhiteSpace(healthCheck.DmarcAnalysis?.DmarcRecord);
        result.Mail.BimiRecord = NullIfWhiteSpace(healthCheck.BimiAnalysis?.BimiRecord);
        result.Mail.MtaStsPolicy = NullIfWhiteSpace(healthCheck.MTASTSAnalysis?.Policy);
        result.Mail.TlsRpt = NullIfWhiteSpace(healthCheck.TLSRPTAnalysis?.TlsRptRecord);

        result.Web.HttpOk = healthCheck.HttpAnalysis?.IsReachable;
        result.Web.HttpsOk = healthCheck.CertificateAnalysis?.IsReachable;
        result.Web.Http2 = healthCheck.HttpAnalysis?.Http2Supported;
        result.Web.Http3 = healthCheck.HttpAnalysis?.Http3Supported;
        result.Web.Hsts = healthCheck.HttpAnalysis?.HstsPresent;

        var certificate = healthCheck.CertificateAnalysis?.Certificate;
        if (certificate != null)
        {
            result.Web.Tls = new TlsChainInfo
            {
                Subject = certificate.Subject,
                Issuer = certificate.Issuer,
                NotAfter = new DateTimeOffset(certificate.NotAfter.ToUniversalTime())
            };
        }

        result.Reputation.WhoisRegistrar = NullIfWhiteSpace(healthCheck.WhoisAnalysis?.Registrar);
        result.Reputation.RdapHandle = NullIfWhiteSpace(healthCheck.RdapAnalysis?.DomainData?.Handle);
        result.Reputation.RpkiValid = healthCheck.RpkiAnalysis?.Results?.Count > 0
            ? healthCheck.RpkiAnalysis.AllValid
            : null;
        result.Reputation.Blacklists = (healthCheck.DNSBLAnalysis?.AllResults ?? new List<DNSBLRecord>())
            .Where(record => record.IsBlackListed && !string.IsNullOrWhiteSpace(record.BlackList))
            .Select(record => record.BlackList)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return result;
    }

    private static List<MxInfo> BuildMxInfos(IReadOnlyCollection<string>? mxRecords)
    {
        var output = new List<MxInfo>();
        foreach (var raw in mxRecords ?? Array.Empty<string>())
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            var parts = raw.Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 2 && int.TryParse(parts[0], out var preference))
            {
                output.Add(new MxInfo
                {
                    Preference = preference,
                    Host = parts[1].Trim().TrimEnd('.')
                });
            }
            else
            {
                output.Add(new MxInfo
                {
                    Preference = 0,
                    Host = raw.Trim().TrimEnd('.')
                });
            }
        }

        return output;
    }

    private static string? NullIfWhiteSpace(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}
