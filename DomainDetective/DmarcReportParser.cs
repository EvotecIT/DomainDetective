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

/// <summary>Parser for zipped DMARC feedback reports.</summary>
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

    /// <summary>Parses the specified zip file and returns individual report records.</summary>
    /// <param name="path">Path to the zipped XML feedback report.</param>
    /// <param name="validationMessages">Optional list collecting schema validation errors.</param>
    public static IEnumerable<DmarcAggregateRecord> ParseZip(string path, IList<string>? validationMessages = null) {
        using var archive = ZipFile.OpenRead(path);
        var entry = archive.Entries.FirstOrDefault(e => e.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase));
        if (entry == null) {
            yield break;
        }

        using var baseStream = entry.Open();
        using var buffer = new MemoryStream();
        baseStream.CopyTo(buffer);
        buffer.Position = 0;

        string nsString;
        using (var nsReader = XmlReader.Create(buffer, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit })) {
            nsReader.MoveToContent();
            nsString = nsReader.NamespaceURI;
        }

        XmlSchemaSet schemas = nsString switch {
            "http://dmarc.org/dmarc-xml/0.1" => V1Schemas.Value,
            "http://dmarc.org/dmarc-xml/2.0" => V2Schemas.Value,
            _ => throw new InvalidOperationException($"Unknown DMARC namespace '{nsString}'.")
        };

        buffer.Position = 0;
        var settings = new XmlReaderSettings {
            ValidationType = ValidationType.Schema,
            Schemas = schemas
        };
        if (validationMessages != null) {
            settings.ValidationEventHandler += (_, e) => validationMessages.Add(e.Message);
        }

        using var reader = XmlReader.Create(buffer, settings);
        XDocument doc = XDocument.Load(reader);
        XNamespace ns = nsString;
        foreach (var record in doc.Descendants(ns + "record")) {
            string rawDomain = record.Element(ns + "identifiers")?
                .Element(ns + "header_from")?.Value ?? string.Empty;
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

            yield return new DmarcAggregateRecord {
                SourceIp = sourceIp,
                HeaderFrom = headerFrom,
                Count = count,
                Dkim = dkim,
                Spf = spf,
                Disposition = disposition
            };
        }
    }

    /// <summary>Parses multiple zipped DMARC reports and returns individual report records.</summary>
    /// <param name="paths">Paths to zipped XML feedback reports.</param>
    public static IEnumerable<DmarcAggregateRecord> ParseMultiple(IEnumerable<string> paths) {
        foreach (var path in paths) {
            var records = ParseZip(path).ToList();
            foreach (var record in records) {
                yield return record;
            }
        }
    }
}
