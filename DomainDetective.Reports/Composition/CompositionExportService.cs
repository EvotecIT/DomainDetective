using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.Reports;

public static class CompositionExportService
{
    public static async Task<CompositionExportResult> ExportAsync(
        CompositionExportRequest request,
        InternalLogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        if (request == null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        var formats = (request.Formats != null && request.Formats.Count > 0)
            ? request.Formats
            : new[] { ReportFormat.Html };

        var flat = CompositionUtilities.Flatten(request.Items ?? Array.Empty<object>());
        if (flat.Count == 0)
        {
            return new CompositionExportResult {
                Items = flat,
                Subjects = Array.Empty<string>(),
                SubjectLabel = string.Empty,
                Reports = Array.Empty<ReportResult>()
            };
        }

        if (request.AutoCollectTtl)
        {
            flat = await CompositionTtlAutoCollector.AddMissingTtlAsync(flat, request.ExecutionOptions, logger, cancellationToken).ConfigureAwait(false);
        }

        var subjects = CompositionUtilities.ExtractSubjects(flat);
        var label = CompositionUtilities.BuildSubjectLabel(subjects);
        logger?.WriteVerbose("Export-DDSecurityReport: composing {0} item(s) across {1} domain(s).", flat.Count, subjects.Count);

        if (request.LogSectionOrder)
        {
            LogSectionOrder(flat, request.Ordering, logger);
        }

        var results = new List<ReportResult>();
        foreach (var format in formats)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var outPath = ReportPathHelper.ResolveOutputPathForFormat(request.ExportPath, request.DefaultOutputDirectory, label, format, formats);
            var sw = Stopwatch.StartNew();
            logger?.WriteVerbose("Export-DDSecurityReport: generating {0} report to {1} (items: {2}, domains: {3}).", format, outPath, flat.Count, subjects.Count);

            try
            {
                if (!CompositionReportDispatcher.TryGenerate(format, request, flat, outPath, out var error))
                {
                    var message = string.IsNullOrWhiteSpace(error) ? $"{format} composition not supported." : error!;
                    logger?.WriteWarning("Export failed: {0}", message);
                    results.Add(new ReportResult {
                        Success = false,
                        FilePath = outPath,
                        Format = format,
                        ErrorMessage = message,
                        GenerationTime = sw.Elapsed
                    });
                    continue;
                }

                sw.Stop();
                if (request.OpenInBrowser && format != ReportFormat.Html)
                {
                    ReportOpenHelper.TryOpen(outPath);
                }

                results.Add(new ReportResult {
                    Success = true,
                    FilePath = outPath,
                    Format = format,
                    FileSize = TryGetFileSize(outPath),
                    GenerationTime = sw.Elapsed
                });
                logger?.WriteVerbose("Export-DDSecurityReport: {0} report generated in {1} ms.", format, sw.ElapsedMilliseconds);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                sw.Stop();
                logger?.WriteWarning("Export failed: {0}", ex.Message);
                results.Add(new ReportResult {
                    Success = false,
                    FilePath = outPath,
                    Format = format,
                    ErrorMessage = ex.Message,
                    GenerationTime = sw.Elapsed
                });
            }
        }

        return new CompositionExportResult {
            Items = flat,
            Subjects = subjects,
            SubjectLabel = label,
            Reports = results
        };
    }

    private static long TryGetFileSize(string path)
    {
        try
        {
            return File.Exists(path) ? new FileInfo(path).Length : 0;
        }
        catch
        {
            return 0;
        }
    }

    private static void LogSectionOrder(IReadOnlyList<object> items, OrderingOptions ordering, InternalLogger? logger)
    {
        if (logger == null)
        {
            return;
        }

        try
        {
            var orderMode = ordering?.SectionOrderMode ?? SectionOrderMode.Canonical;
            var custom = SectionOrdering.NormalizeSectionList(ordering?.SectionOrder ?? Array.Empty<string>());
            var inputOrder = SectionOrdering.DetermineSectionOrderByDomain(items);
            var grouped = CompositionBuilder.GroupBySubject(items);
            foreach (var kv in grouped)
            {
                var domain = kv.Key;
                var b = kv.Value;
                var present = new List<string>();
                if (b.Mx != null) present.Add("MX");
                if (b.Spf != null) present.Add("SPF");
                if (b.Dkim.Count > 0) present.Add("DKIM");
                if (b.Dmarc != null) present.Add("DMARC");
                if (b.Arc != null) present.Add("ARC");
                if (b.Bimi != null) present.Add("BIMI");
                if (b.Dnsbl != null) present.Add("DNSBL");
                if (b.Classification != null) present.Add("Classification");
                if (b.Mtasts != null) present.Add("MTA-STS");
                if (b.TlsRpt != null) present.Add("TLS-RPT");
                if (b.Ns != null) present.Add("NS");
                if (b.Soa != null) present.Add("SOA");
                if (b.ZoneTransfer != null) present.Add("ZoneTransfer");
                if (b.Wildcard != null) present.Add("Wildcard");
                if (b.Caa != null) present.Add("CAA");
                if (b.Dnssec != null) present.Add("DNSSEC");
                if (b.Dane != null) present.Add("DANE");
                if (b.Rpki != null) present.Add("RPKI");
                if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null) present.Add("MAILTLS");
                var input = inputOrder.TryGetValue(domain, out var list) ? list : null;
                var resolved = SectionOrdering.ResolveOrder(orderMode, present, input, custom);
                if (resolved.Count > 0)
                {
                    logger.WriteVerbose("Export-DDSecurityReport: section order for {0}: {1}", domain, string.Join(", ", resolved));
                }
            }
        }
        catch (Exception ex)
        {
            logger.WriteVerbose("Export-DDSecurityReport: failed to compute section order: {0}", ex.Message);
        }
    }
}
