using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using OfficeIMO.Word;
using OfficeIMO.Word.Pdf;

namespace DomainDetective.Reports.Office;

/// <summary>Writes the selected paper artifacts from one owned Word document.</summary>
internal static class WordReportExport {
    internal static IReadOnlyList<ReportResult> Generate(IReadOnlyDictionary<ReportFormat, string> outputs,
        Func<WordDocument> build, WordToPdfOptions? pdfOptions = null, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        if (outputs == null) { throw new ArgumentNullException(nameof(outputs)); }
        if (outputs.Keys.Any(format => format is not (ReportFormat.Word or ReportFormat.Pdf))) {
            throw new ArgumentException("Paper outputs support only Word and PDF.", nameof(outputs));
        }
        if (outputs.Count == 0) { return Array.Empty<ReportResult>(); }
        var paths = outputs.ToDictionary(pair => pair.Key, pair => Path.GetFullPath(pair.Value));
        if (paths.Values.Distinct(StringComparer.OrdinalIgnoreCase).Count() != paths.Count) {
            throw new ArgumentException("Word and PDF must have different output paths.", nameof(outputs));
        }
        var results = new List<ReportResult>();
        var timer = Stopwatch.StartNew();
        using WordDocument document = build();
        cancellationToken.ThrowIfCancellationRequested();
        foreach (var output in paths) {
            cancellationToken.ThrowIfCancellationRequested();
            var result = new ReportResult { Format = output.Key, FilePath = output.Value };
            try {
                string? directory = Path.GetDirectoryName(output.Value);
                if (directory != null) { Directory.CreateDirectory(directory); }
                if (output.Key == ReportFormat.Word) { document.Save(output.Value); }
                else { document.SaveAsPdf(output.Value, pdfOptions, cancellationToken); }
                cancellationToken.ThrowIfCancellationRequested();
                result.Success = true;
                result.FileSize = new FileInfo(output.Value).Length;
            } catch (Exception ex) when (ex is not OperationCanceledException) {
                result.ErrorMessage = ex.Message;
            }
            result.GenerationTime = timer.Elapsed;
            results.Add(result);
        }
        return results;
    }
}
