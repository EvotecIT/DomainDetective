using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.TimeSeries.DmarcAggregate;

/// <summary>Provides dmarc aggregate ingest result functionality.</summary>
public sealed class DmarcAggregateIngestResult
{
    /// <summary>Gets the snapshots value.</summary>
    public List<DmarcAggregateSnapshot> Snapshots { get; } = new();
    /// <summary>Gets the snapshot paths value.</summary>
    public List<string> SnapshotPaths { get; } = new();
    /// <summary>Gets the errors value.</summary>
    public List<string> Errors { get; } = new();
}

/// <summary>Provides dmarc aggregate ingestion functionality.</summary>
public static class DmarcAggregateIngestion
{
    private static readonly string[] Extensions = { ".xml", ".gz", ".gzip", ".zip" };

    /// <summary>Executes the ingest from path operation.</summary>
    public static DmarcAggregateIngestResult IngestFromPath(string path, DmarcAggregateTimeSeriesStore store, bool deduplicate = true)
    {
        if (store == null) throw new ArgumentNullException(nameof(store));

        var result = new DmarcAggregateIngestResult();
        var files = ReportFileEnumerator.EnumerateFiles(path, Extensions).ToList();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in files)
        {
            try
            {
                var report = DmarcReportParser.Parse(file);
                if (deduplicate)
                {
                    var key = $"{report.ReportId}|{report.RangeBeginUtc?.UtcDateTime:o}|{report.RangeEndUtc?.UtcDateTime:o}|{report.ReporterOrgName}|{report.PolicyPublished?.Domain}";
                    if (!string.IsNullOrWhiteSpace(report.ReportId) && !seen.Add(key))
                    {
                        continue;
                    }
                }

                var snapshot = DmarcAggregateSnapshotBuilder.Build(report, source: "File", sourceId: file);
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

    /// <summary>Executes the ingest from imap async operation.</summary>
    public static async Task<DmarcAggregateIngestResult> IngestFromImapAsync(ImapAttachmentIngestOptions options, DmarcAggregateTimeSeriesStore store, bool deduplicate = true, CancellationToken cancellationToken = default)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));
        if (store == null) throw new ArgumentNullException(nameof(store));

        var result = new DmarcAggregateIngestResult();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var savedPaths = new List<string>();
        var savedLock = new object();

        bool Include(string fileName)
        {
            var ext = Path.GetExtension(fileName ?? string.Empty);
            if (string.IsNullOrWhiteSpace(ext)) return false;
            return Extensions.Contains(ext, StringComparer.OrdinalIgnoreCase);
        }

        Task<DmarcAggregateSnapshot?> Parse(Stream stream, string fileName, CancellationToken ct)
        {
            var report = DmarcReportParser.Parse(stream, fileName, validationMessages: null, maxUncompressedBytes: options.MaxAttachmentBytes);
            if (deduplicate)
            {
                var key = $"{report.ReportId}|{report.RangeBeginUtc?.UtcDateTime:o}|{report.RangeEndUtc?.UtcDateTime:o}|{report.ReporterOrgName}|{report.PolicyPublished?.Domain}";
                if (!string.IsNullOrWhiteSpace(report.ReportId) && !seen.Add(key))
                {
                    return Task.FromResult<DmarcAggregateSnapshot?>(null);
                }
            }

            var snapshot = DmarcAggregateSnapshotBuilder.Build(report, source: "IMAP", sourceId: fileName);
            var outPath = store.SaveSnapshot(snapshot);
            lock (savedLock)
            {
                savedPaths.Add(outPath);
            }
            return Task.FromResult<DmarcAggregateSnapshot?>(snapshot);
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
}
