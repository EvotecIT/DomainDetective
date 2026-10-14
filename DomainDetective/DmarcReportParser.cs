using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;
using DomainDetective.Helpers;

namespace DomainDetective;

/// <summary>Parses DMARC feedback reports from various formats.</summary>
public static class DmarcReportParser {
    private static readonly Lazy<XmlSchemaSet> V1Schemas = new(() => LoadSchemas("DomainDetective.Definitions.DmarcAggregateReport_v1.xsd"));
    private static readonly Lazy<XmlSchemaSet> V2Schemas = new(() => LoadSchemas("DomainDetective.Definitions.DmarcAggregateReport_v2.xsd"));
    private static readonly Lazy<XmlSchemaSet> CurrentSchemas = new(() => LoadSchemas("DomainDetective.Definitions.DmarcAggregateReport_rfc9990.xsd"));
    private static readonly Lazy<XmlSchemaSet> LegacyPlainSchemas = new(() => LoadLegacySchemas(null, "unqualified"));
    private static readonly Lazy<XmlSchemaSet> LegacyQualifiedSchemas = new(() => LoadLegacySchemas("http://dmarc.org/dmarc-xml/0.1", "qualified"));
    private static readonly Lazy<XmlSchemaSet> LegacyUnqualifiedSchemas = new(() => LoadLegacySchemas("http://dmarc.org/dmarc-xml/0.1", "unqualified"));

    private static XmlSchemaSet LoadLegacySchemas(string? targetNamespace, string elementForm) {
        using var stream = typeof(DmarcReportParser).Assembly.GetManifestResourceStream("DomainDetective.Definitions.DmarcAggregateReport_legacy.xsd")!;
        var schema = XElement.Load(stream);
        schema.SetAttributeValue("targetNamespace", targetNamespace);
        schema.SetAttributeValue("elementFormDefault", elementForm);
        if (targetNamespace != null) schema.SetAttributeValue("xmlns", targetNamespace);
        using var reader = schema.CreateReader();
        var set = new XmlSchemaSet { XmlResolver = null };
        set.Add(null, reader);
        return set;
    }

    private static XmlSchemaSet LoadSchemas(string resourceName) {
        var assembly = typeof(DmarcReportParser).Assembly;
        using var stream = assembly.GetManifestResourceStream(resourceName) ??
            throw new InvalidOperationException($"Schema resource '{resourceName}' not found.");
        var set = new XmlSchemaSet { XmlResolver = null };
        using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
        set.Add(null, reader);
        return set;
    }

    /// <summary>Parses a DMARC feedback report from the specified path.</summary>
    /// <param name="path">Path to a .xml, .gz, or .zip report.</param>
    /// <param name="validationMessages">Optional list collecting schema validation errors.</param>
    /// <returns>The parsed aggregate report.</returns>
    public static DmarcAggregateReport Parse(string path, IList<string>? validationMessages = null) {
        return Parse(path, validationMessages, TimeSeries.ReportReadLimits.DefaultUncompressedBytes);
    }

    /// <summary>Parses a report file with an explicit expansion limit.</summary>
    /// <param name="path">Path to a .xml, .gz, or .zip report.</param>
    /// <param name="validationMessages">Optional schema validation errors.</param>
    /// <param name="maxUncompressedBytes">Maximum expanded bytes; 0 means unlimited.</param>
    /// <returns>The parsed aggregate report.</returns>
    public static DmarcAggregateReport Parse(string path, IList<string>? validationMessages, long maxUncompressedBytes) {
        using var file = File.OpenRead(path);
        return Parse(file, path, validationMessages, maxUncompressedBytes);
    }

    /// <summary>Parses a DMARC feedback report from a stream.</summary>
    /// <param name="stream">Input stream containing the report data.</param>
    /// <param name="name">Optional name used to determine the format (.xml, .gz, .zip).</param>
    /// <param name="validationMessages">Optional list collecting schema validation errors.</param>
    /// <returns>The parsed aggregate report.</returns>
    public static DmarcAggregateReport Parse(Stream stream, string? name = null, IList<string>? validationMessages = null) {
        return Parse(stream, name, validationMessages, maxUncompressedBytes: TimeSeries.ReportReadLimits.DefaultUncompressedBytes);
    }

    /// <summary>Parses a DMARC feedback report from a stream with size limits.</summary>
    /// <param name="stream">Input stream containing the report data.</param>
    /// <param name="name">Optional name used to determine the format (.xml, .gz, .zip).</param>
    /// <param name="validationMessages">Optional list collecting schema validation errors.</param>
    /// <param name="maxUncompressedBytes">Maximum uncompressed size to read (0 means unlimited).</param>
    /// <returns>The parsed aggregate report.</returns>
    public static DmarcAggregateReport Parse(Stream stream, string? name, IList<string>? validationMessages, long maxUncompressedBytes) {
        if (maxUncompressedBytes < 0) {
            throw new ArgumentOutOfRangeException(nameof(maxUncompressedBytes), "maxUncompressedBytes must be >= 0 (0 means unlimited).");
        }

        string ext = name != null ? Path.GetExtension(name).ToLowerInvariant() : ".xml";
        using var buffer = new MemoryStream();

        if (ext == ".zip") {
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            var entry = archive.Entries.FirstOrDefault(e => e.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase));
            if (entry == null) {
                return new DmarcAggregateReport();
            }

            if (maxUncompressedBytes > 0 && entry.Length > maxUncompressedBytes) {
                throw new IOException($"DMARC ZIP entry '{entry.FullName}' exceeds max uncompressed size {maxUncompressedBytes} bytes.");
            }

            using var entryStream = entry.Open();
            CopyToWithLimit(entryStream, buffer, maxUncompressedBytes);
        } else if (ext == ".gz" || ext == ".gzip") {
            using var gz = new GZipStream(stream, CompressionMode.Decompress, leaveOpen: true);
            CopyToWithLimit(gz, buffer, maxUncompressedBytes);
        } else {
            CopyToWithLimit(stream, buffer, maxUncompressedBytes);
        }

        buffer.Position = 0;

        XDocument doc;
        using (var reader = XmlReader.Create(buffer, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null })) {
            doc = XDocument.Load(reader);
        }
        string nsString = doc.Root?.Name.NamespaceName ?? string.Empty;
        XNamespace ns = nsString == "http://dmarc.org/dmarc-xml/0.1" && doc.Root?.Element("report_metadata") != null
            ? XNamespace.None : nsString;
        XmlSchemaSet schemas = nsString switch {
            "" => LegacyPlainSchemas.Value,
            "http://dmarc.org/dmarc-xml/0.1" when doc.Root?.Element(ns + "report_metadata") != null =>
                ns == XNamespace.None ? LegacyUnqualifiedSchemas.Value : LegacyQualifiedSchemas.Value,
            "http://dmarc.org/dmarc-xml/0.1" => V1Schemas.Value,
            "http://dmarc.org/dmarc-xml/2.0" => V2Schemas.Value,
            "urn:ietf:params:xml:ns:dmarc-2.0" => CurrentSchemas.Value,
            _ => throw new InvalidOperationException($"Unknown DMARC namespace '{nsString}'. Supported formats are legacy reports with no namespace, v1 (0.1), v2 (2.0), and RFC 9990 (urn:ietf:params:xml:ns:dmarc-2.0).")
        };
        var collected = validationMessages ?? new List<string>();
        doc.Validate(schemas, validationMessages != null ? (_, e) => collected.Add(e.Message) : null);

        var report = new DmarcAggregateReport {
            PolicyPublished = ParsePolicy(doc.Root?.Element(ns + "policy_published"), ns),
            XmlNamespace = nsString,
            Version = doc.Root?.Element(ns + "version")?.Value
        };
        report.ValidationMessages.AddRange(collected);
        var extensions = doc.Root?.Element(ns + "extension")?.Elements();
        if (extensions != null) report.Extensions.AddRange(extensions.Select(element => element.ToString(SaveOptions.DisableFormatting)));
        var meta = doc.Root?.Element(ns + "report_metadata");
        if (meta != null)
        {
            report.ReportId = meta.Element(ns + "report_id")?.Value;
            report.ReporterOrgName = meta.Element(ns + "org_name")?.Value;
            report.ReporterEmail = meta.Element(ns + "email")?.Value;
            report.Generator = meta.Element(ns + "generator")?.Value;
            report.ExtraContactInfo = meta.Element(ns + "extra_contact_info")?.Value;
            report.ReportedErrors.AddRange(meta.Elements(ns + "error").Select(element => element.Value));
            var dr = meta.Element(ns + "date_range");
            if (dr != null)
            {
                report.RangeBeginUtc = ParseReportDate(dr.Element(ns + "begin")?.Value, "begin", report, validationMessages);
                report.RangeEndUtc = ParseReportDate(dr.Element(ns + "end")?.Value, "end", report, validationMessages);
            }
        }

        foreach (var record in doc.Root?.Elements(ns + "record") ?? Enumerable.Empty<XElement>()) {
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
            string sourceIp = (row?.Element(ns + "source_ip")?.Value ?? string.Empty).Trim();
            bool validIp = !sourceIp.Contains('%') && !sourceIp.Contains('[') && !sourceIp.Contains(']')
                && IPAddress.TryParse(sourceIp, out var address)
                && (address.AddressFamily == AddressFamily.InterNetworkV6 || string.Equals(address.ToString(), sourceIp, StringComparison.Ordinal));
            if (!validIp) {
                string error = $"Report source_ip '{sourceIp}' is not an IPv4 or IPv6 address literal.";
                ReportValidationError(error, report, validationMessages);
            }
            string dkim = row?.Element(ns + "policy_evaluated")?.Element(ns + "dkim")?.Value ?? string.Empty;
            string spf = row?.Element(ns + "policy_evaluated")?.Element(ns + "spf")?.Value ?? string.Empty;
            string disposition = row?.Element(ns + "policy_evaluated")?.Element(ns + "disposition")?.Value ?? string.Empty;
            string countStr = row?.Element(ns + "count")?.Value ?? "1";
            if (!int.TryParse(countStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out int count) || count < 0) {
                if (meta != null || nsString == "urn:ietf:params:xml:ns:dmarc-2.0") {
                    ReportValidationError($"Report count '{countStr}' cannot be represented as a nonnegative Int32 message count.", report, validationMessages);
                    count = 0;
                } else count = 1; // Compatibility for the existing partial legacy-report API.
            }

            var rec = new DmarcAggregateRecord {
                SourceIp = sourceIp,
                HeaderFrom = headerFrom,
                Count = count,
                Dkim = dkim,
                Spf = spf,
                Disposition = disposition,
                EnvelopeFrom = record.Element(ns + "identifiers")?.Element(ns + "envelope_from")?.Value,
                EnvelopeTo = record.Element(ns + "identifiers")?.Element(ns + "envelope_to")?.Value
            };
            rec.Extensions.AddRange(record.Elements().Where(element => element.Name != ns + "row"
                && element.Name != ns + "identifiers" && element.Name != ns + "auth_results")
                .Select(element => element.ToString(SaveOptions.DisableFormatting)));

            // Reasons
            var reasons = row?.Element(ns + "policy_evaluated")?.Elements(ns + "reason");
            if (reasons != null)
            {
                foreach (var r in reasons)
                {
                    var t = r.Element(ns + "type")?.Value;
                    var c = r.Element(ns + "comment")?.Value;
                    if (string.IsNullOrWhiteSpace(t) && string.IsNullOrWhiteSpace(c)) continue;
                    var s = string.IsNullOrWhiteSpace(c) ? (t ?? string.Empty) : $"{t}: {c}";
                    if (!string.IsNullOrWhiteSpace(s)) rec.Reasons.Add(s);
                }
            }

            // Auth results
            var auth = record.Element(ns + "auth_results");
            if (auth != null)
            {
                foreach (var spfAuth in auth.Elements(ns + "spf")) {
                    rec.SpfResults.Add(new DmarcSpfAuthenticationResult {
                        Domain = spfAuth.Element(ns + "domain")?.Value,
                        Result = spfAuth.Element(ns + "result")?.Value,
                        Scope = spfAuth.Element(ns + "scope")?.Value,
                        HumanResult = spfAuth.Element(ns + "human_result")?.Value
                    });
                }
                foreach (var dkimAuth in auth.Elements(ns + "dkim")) {
                    rec.DkimResults.Add(new DmarcDkimAuthenticationResult {
                        Domain = dkimAuth.Element(ns + "domain")?.Value,
                        Selector = dkimAuth.Element(ns + "selector")?.Value,
                        Result = dkimAuth.Element(ns + "result")?.Value,
                        HumanResult = dkimAuth.Element(ns + "human_result")?.Value
                    });
                }
                var firstSpf = rec.SpfResults.FirstOrDefault();
                rec.SpfDomain = firstSpf?.Domain;
                rec.SpfResult = firstSpf?.Result;
                var firstDkim = rec.DkimResults.FirstOrDefault();
                rec.DkimDomain = firstDkim?.Domain;
                rec.DkimSelector = firstDkim?.Selector;
                rec.DkimResult = firstDkim?.Result;
            }

            report.Records.Add(rec);
        }

        return report;
    }

    private static DateTimeOffset? ParseReportDate(string? value, string field, DmarcAggregateReport report, IList<string>? messages) {
        if (value == null) return null;
        if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long seconds)
            && seconds >= -62135596800L && seconds <= 253402300799L) return DateTimeOffset.FromUnixTimeSeconds(seconds);
        ReportValidationError($"Report date_range/{field} '{value}' is outside the supported UTC timestamp range.", report, messages);
        return null;
    }

    private static void ReportValidationError(string error, DmarcAggregateReport report, IList<string>? messages) {
        if (messages == null) throw new XmlSchemaValidationException(error);
        messages.Add(error);
        report.ValidationMessages.Add(error);
    }

    private static void CopyToWithLimit(Stream source, Stream destination, long maxBytes) {
        if (maxBytes <= 0) {
            source.CopyTo(destination);
            return;
        }

        var buf = new byte[81920];
        long total = 0;
        int read;
        while ((read = source.Read(buf, 0, buf.Length)) > 0) {
            total += read;
            if (total > maxBytes) {
                throw new IOException($"Stream exceeds max size {maxBytes} bytes.");
            }
            destination.Write(buf, 0, read);
        }
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
        result.Testing = policy.Element(ns + "testing")?.Value;
        result.DiscoveryMethod = policy.Element(ns + "discovery_method")?.Value;

        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "domain", "adkim", "aspf", "p", "sp", "pct", "fo", "np", "testing", "discovery_method"
        };
        foreach (var child in policy.Elements()) {
            if (child.Name.Namespace != ns || !known.Contains(child.Name.LocalName)) {
                result.Extensions[child.Name.Namespace == ns ? child.Name.LocalName : child.Name.ToString()] = child.Value;
            }
        }

        result.RequestedReportingPolicy = ComputeReportingPolicy(result.Fo);
        return result;
    }

    private static string ComputeReportingPolicy(string? fo)
    {
        if (string.IsNullOrWhiteSpace(fo)) return "All underlying mechanisms fail to produce an aligned pass (default, fo=0)";
          var tokens = fo!.Split(new [] { ':', ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);
        var parts = new List<string>();
        foreach (var t in tokens)
        {
            switch (t.Trim().ToLowerInvariant())
            {
                case "0": parts.Add("All underlying mechanisms fail to produce an aligned pass"); break;
                case "1": parts.Add("Any underlying mechanism fails to produce an aligned pass"); break;
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
