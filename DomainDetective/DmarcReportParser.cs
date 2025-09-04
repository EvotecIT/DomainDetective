using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;
using DomainDetective.Helpers;

namespace DomainDetective;

/// <summary>Parses DMARC feedback reports from various formats.</summary>
public static class DmarcReportParser {
    private static readonly Lazy<XmlSchemaSet> V1Schemas = new(() => LoadSchemas("DomainDetective.Definitions.DmarcAggregateReport_v1.xsd"));
    private static readonly Lazy<XmlSchemaSet> V2Schemas = new(() => LoadSchemas("DomainDetective.Definitions.DmarcAggregateReport_v2.xsd"));

    private static XmlSchemaSet LoadSchemas(string resourceName) {
        var assembly = typeof(DmarcReportParser).Assembly;
        using var stream = assembly.GetManifestResourceStream(resourceName) ??
            throw new InvalidOperationException($"Schema resource '{resourceName}' not found.");
        var set = new XmlSchemaSet();
        set.Add(null, XmlReader.Create(stream));
        return set;
    }

    /// <summary>Parses a DMARC feedback report from the specified path.</summary>
    /// <param name="path">Path to a .xml, .gz, or .zip report.</param>
    /// <param name="validationMessages">Optional list collecting schema validation errors.</param>
    /// <returns>The parsed aggregate report.</returns>
    public static DmarcAggregateReport Parse(string path, IList<string>? validationMessages = null) {
        using var file = File.OpenRead(path);
        return Parse(file, path, validationMessages);
    }

    /// <summary>Parses a DMARC feedback report from a stream.</summary>
    /// <param name="stream">Input stream containing the report data.</param>
    /// <param name="name">Optional name used to determine the format (.xml, .gz, .zip).</param>
    /// <param name="validationMessages">Optional list collecting schema validation errors.</param>
    /// <returns>The parsed aggregate report.</returns>
    public static DmarcAggregateReport Parse(Stream stream, string? name = null, IList<string>? validationMessages = null) {
        string ext = name != null ? Path.GetExtension(name).ToLowerInvariant() : ".xml";
        using var buffer = new MemoryStream();

        if (ext == ".zip") {
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            var entry = archive.Entries.FirstOrDefault(e => e.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase));
            if (entry == null) {
                return new DmarcAggregateReport();
            }

            using var entryStream = entry.Open();
            entryStream.CopyTo(buffer);
        } else if (ext == ".gz" || ext == ".gzip") {
            using var gz = new GZipStream(stream, CompressionMode.Decompress, leaveOpen: true);
            gz.CopyTo(buffer);
        } else {
            stream.CopyTo(buffer);
        }

        buffer.Position = 0;

        string nsString;
        using (var nsReader = XmlReader.Create(buffer, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit })) {
            nsReader.MoveToContent();
            nsString = nsReader.NamespaceURI;
        }

        buffer.Position = 0;

        XmlSchemaSet schemas = nsString switch {
            "http://dmarc.org/dmarc-xml/0.1" => V1Schemas.Value,
            "http://dmarc.org/dmarc-xml/2.0" => V2Schemas.Value,
            _ => throw new InvalidOperationException($"Unknown DMARC namespace '{nsString}'. Supported versions are v1 (0.1) and v2 (2.0).")
        };

        var settings = new XmlReaderSettings {
            ValidationType = ValidationType.Schema,
            Schemas = schemas
        };
        var collected = validationMessages ?? new List<string>();
        if (validationMessages != null) {
            settings.ValidationEventHandler += (_, e) => collected.Add(e.Message);
        }

        using var reader = XmlReader.Create(buffer, settings);
        XDocument doc = XDocument.Load(reader);
        XNamespace ns = nsString;

        var report = new DmarcAggregateReport {
            PolicyPublished = ParsePolicy(doc.Root?.Element(ns + "policy_published"), ns)
        };
        var meta = doc.Root?.Element(ns + "report_metadata");
        if (meta != null)
        {
            report.ReportId = meta.Element(ns + "report_id")?.Value;
            var dr = meta.Element(ns + "date_range");
            if (dr != null)
            {
                if (long.TryParse(dr.Element(ns + "begin")?.Value, out var begin))
                    report.RangeBeginUtc = System.DateTimeOffset.FromUnixTimeSeconds(begin);
                if (long.TryParse(dr.Element(ns + "end")?.Value, out var end))
                    report.RangeEndUtc = System.DateTimeOffset.FromUnixTimeSeconds(end);
            }
        }
        report.ValidationMessages.AddRange(collected);

        foreach (var record in doc.Descendants(ns + "record")) {
            string rawDomain = record.Element(ns + "identifiers")?.Element(ns + "header_from")?.Value ?? string.Empty;
            if (string.IsNullOrEmpty(rawDomain)) {
                continue;
            }

            string headerFrom;
            try {
                headerFrom = DomainHelper.ValidateIdn(rawDomain);
            } catch (ArgumentException) {
                continue;
            }

            var row = record.Element(ns + "row");
            string sourceIp = row?.Element(ns + "source_ip")?.Value ?? string.Empty;
            string dkim = row?.Element(ns + "policy_evaluated")?.Element(ns + "dkim")?.Value ?? string.Empty;
            string spf = row?.Element(ns + "policy_evaluated")?.Element(ns + "spf")?.Value ?? string.Empty;
            string disposition = row?.Element(ns + "policy_evaluated")?.Element(ns + "disposition")?.Value ?? string.Empty;
            string countStr = row?.Element(ns + "count")?.Value ?? "1";
            if (!int.TryParse(countStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out int count) || count < 0) {
                count = 1;
            }

            report.Records.Add(new DmarcAggregateRecord {
                SourceIp = sourceIp,
                HeaderFrom = headerFrom,
                Count = count,
                Dkim = dkim,
                Spf = spf,
                Disposition = disposition
            });
        }

        return report;
    }

    private static DmarcPolicyPublished ParsePolicy(XElement? policy, XNamespace ns) {
        var result = new DmarcPolicyPublished();
        if (policy == null) {
            return result;
        }

        result.Domain = policy.Element(ns + "domain")?.Value ?? string.Empty;
        result.Adkim = policy.Element(ns + "adkim")?.Value;
        result.Aspf = policy.Element(ns + "aspf")?.Value;
        result.P = policy.Element(ns + "p")?.Value;
        result.Sp = policy.Element(ns + "sp")?.Value;
        result.Pct = policy.Element(ns + "pct")?.Value;
        result.Fo = policy.Element(ns + "fo")?.Value;
        result.Np = policy.Element(ns + "np")?.Value;

        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "domain", "adkim", "aspf", "p", "sp", "pct", "fo", "np"
        };
        foreach (var child in policy.Elements()) {
            if (!known.Contains(child.Name.LocalName)) {
                result.Extensions[child.Name.LocalName] = child.Value;
            }
        }

        result.RequestedReportingPolicy = ComputeReportingPolicy(result.Fo);
        return result;
    }

    private static string ComputeReportingPolicy(string? fo)
    {
        if (string.IsNullOrWhiteSpace(fo)) return "any failure (default, fo=0)";
          var tokens = fo!.Split(new [] { ':', ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);
        var parts = new List<string>();
        foreach (var t in tokens)
        {
            switch (t.Trim().ToLowerInvariant())
            {
                case "0": parts.Add("any failure (aligned)"); break;
                case "1": parts.Add("all failures (per-mechanism)"); break;
                case "d": parts.Add("DKIM failure"); break;
                case "s": parts.Add("SPF failure"); break;
                default: parts.Add(t); break;
            }
        }
        return string.Join(", ", parts);
    }

    /// <summary>Parses multiple DMARC reports and returns individual records.</summary>
    /// <param name="paths">Paths to report files.</param>
    public static IEnumerable<DmarcAggregateRecord> ParseMultiple(IEnumerable<string> paths) {
        foreach (var path in paths) {
            var report = Parse(path);
            foreach (var record in report.Records) {
                yield return record;
            }
        }
    }
}
