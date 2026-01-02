using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.TimeSeries.TlsRpt;

public sealed class TlsRptIngestResult
{
    public List<TlsRptSnapshot> Snapshots { get; } = new();
    public List<string> SnapshotPaths { get; } = new();
    public List<string> Errors { get; } = new();
}

public static class TlsRptIngestion
{
    private static readonly string[] Extensions = { ".json", ".gz", ".gzip", ".zip" };

    public static TlsRptIngestResult IngestFromPath(string domain, string path, TlsRptTimeSeriesStore store, bool deduplicate = true)
    {
        if (store == null) throw new ArgumentNullException(nameof(store));

        var result = new TlsRptIngestResult();
        var files = ReportFileEnumerator.EnumerateFiles(path, Extensions).ToList();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in files)
        {
            try
            {
                var report = TlsRptReportParser.Parse(file);
                EnsureReportMatchesDomain(report, domain);
                var snapshot = TlsRptSnapshotBuilder.Build(report, domain, source: "File", sourceId: file);
                if (deduplicate)
                {
                    var key = $"{snapshot.Domain}|{snapshot.ReportId}|{snapshot.RangeBeginUtc?.UtcDateTime:o}|{snapshot.RangeEndUtc?.UtcDateTime:o}|{snapshot.ReporterOrgName}";
                    if (!string.IsNullOrWhiteSpace(snapshot.ReportId) && !seen.Add(key))
                    {
                        continue;
                    }
                }

                var outPath = store.SaveSnapshot(snapshot);
                result.Snapshots.Add(snapshot);
                result.SnapshotPaths.Add(outPath);
            }
            catch (Exception ex)
            {
                result.Errors.Add($"Failed to parse '{file}': {ex.Message}");
            }
        }

        return result;
    }

    public static async Task<TlsRptIngestResult> IngestFromImapAsync(string domain, ImapAttachmentIngestOptions options, TlsRptTimeSeriesStore store, bool deduplicate = true, CancellationToken cancellationToken = default)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));
        if (store == null) throw new ArgumentNullException(nameof(store));

        var result = new TlsRptIngestResult();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var savedPaths = new List<string>();
        var savedLock = new object();

        bool Include(string fileName)
        {
            var ext = Path.GetExtension(fileName ?? string.Empty);
            if (string.IsNullOrWhiteSpace(ext)) return false;
            return Extensions.Contains(ext, StringComparer.OrdinalIgnoreCase);
        }

        Task<TlsRptSnapshot?> Parse(Stream stream, string fileName, CancellationToken ct)
        {
            var report = TlsRptReportParser.Parse(stream, fileName, options.MaxAttachmentBytes);
            EnsureReportMatchesDomain(report, domain);
            var snapshot = TlsRptSnapshotBuilder.Build(report, domain, source: "IMAP", sourceId: fileName);
            if (deduplicate)
            {
                var key = $"{snapshot.Domain}|{snapshot.ReportId}|{snapshot.RangeBeginUtc?.UtcDateTime:o}|{snapshot.RangeEndUtc?.UtcDateTime:o}|{snapshot.ReporterOrgName}";
                if (!string.IsNullOrWhiteSpace(snapshot.ReportId) && !seen.Add(key))
                {
                    return Task.FromResult<TlsRptSnapshot?>(null);
                }
            }

            var outPath = store.SaveSnapshot(snapshot);
            lock (savedLock)
            {
                savedPaths.Add(outPath);
            }

            return Task.FromResult<TlsRptSnapshot?>(snapshot);
        }

        var ingest = await ImapAttachmentIngestor.IngestAsync(options, Include, Parse, cancellationToken).ConfigureAwait(false);
        result.Snapshots.AddRange(ingest.Items);
        result.Errors.AddRange(ingest.Errors);
        lock (savedLock)
        {
            result.SnapshotPaths.AddRange(savedPaths);
        }

        return result;
    }

    private static void EnsureReportMatchesDomain(TlsRptReport report, string expectedDomain)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));

        var expected = NormalizeDomain(expectedDomain);
        if (string.IsNullOrWhiteSpace(expected))
        {
            return;
        }

        var policyDomains = (report.Policies ?? new List<TlsRptPolicyResult>())
            .Select(p => p?.Policy?.PolicyDomain)
            .Where(pd => !string.IsNullOrWhiteSpace(pd))
            .Select(pd => NormalizeDomain(pd!))
            .Where(pd => !string.IsNullOrWhiteSpace(pd))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // Some report generators omit policy-domain; accept but can't validate.
        if (policyDomains.Count == 0)
        {
            return;
        }

        if (!policyDomains.Contains(expected, StringComparer.OrdinalIgnoreCase))
        {
            throw new FormatException($"TLS-RPT report policy-domain mismatch: expected '{expected}', found '{string.Join(", ", policyDomains)}'.");
        }
    }

    private static string NormalizeDomain(string value)
    {
        return (value ?? string.Empty).Trim().TrimEnd('.');
    }
}

