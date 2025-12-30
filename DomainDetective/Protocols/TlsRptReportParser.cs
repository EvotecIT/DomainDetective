using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;

namespace DomainDetective;

/// <summary>Parses SMTP TLS Reporting (TLS-RPT) JSON reports from .json, .gz, or .zip formats.</summary>
public static class TlsRptReportParser
{
    /// <summary>Parses a TLS-RPT JSON report from a file path.</summary>
    public static TlsRptReport Parse(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Path is required.", nameof(path));
        using var file = File.OpenRead(path);
        return Parse(file, path);
    }

    /// <summary>Parses a TLS-RPT JSON report from a stream.</summary>
    public static TlsRptReport Parse(Stream stream, string? name = null)
    {
        return Parse(stream, name, maxUncompressedBytes: 0);
    }

    /// <summary>Parses a TLS-RPT JSON report from a stream with size limits.</summary>
    /// <param name="stream">Input stream containing the report data.</param>
    /// <param name="name">Optional name used to determine the format (.json, .gz, .zip).</param>
    /// <param name="maxUncompressedBytes">Maximum uncompressed size to read (0 means unlimited).</param>
    public static TlsRptReport Parse(Stream stream, string? name, long maxUncompressedBytes)
    {
        if (stream == null) throw new ArgumentNullException(nameof(stream));
        if (maxUncompressedBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxUncompressedBytes), "maxUncompressedBytes must be >= 0 (0 means unlimited).");
        }

        var ext = name != null ? Path.GetExtension(name).ToLowerInvariant() : ".json";
        using var buffer = new MemoryStream();

        if (ext == ".zip")
        {
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            var entry = archive.Entries.FirstOrDefault(e => e.FullName.EndsWith(".json", StringComparison.OrdinalIgnoreCase));
            if (entry == null)
            {
                throw new FormatException("ZIP archive does not contain a .json TLS-RPT report.");
            }

            if (maxUncompressedBytes > 0 && entry.Length > maxUncompressedBytes)
            {
                throw new IOException($"TLS-RPT ZIP entry '{entry.FullName}' exceeds max uncompressed size {maxUncompressedBytes} bytes.");
            }

            using var entryStream = entry.Open();
            CopyToWithLimit(entryStream, buffer, maxUncompressedBytes);
        }
        else if (ext == ".gz" || ext == ".gzip")
        {
            using var gz = new GZipStream(stream, CompressionMode.Decompress, leaveOpen: true);
            CopyToWithLimit(gz, buffer, maxUncompressedBytes);
        }
        else
        {
            CopyToWithLimit(stream, buffer, maxUncompressedBytes);
        }

        buffer.Position = 0;
        using var doc = JsonDocument.Parse(buffer);
        ValidateSchema(doc.RootElement);

        var root = doc.RootElement;
        var report = new TlsRptReport
        {
            OrganizationName = root.GetProperty("organization-name").GetString() ?? string.Empty,
            ContactInfo = root.TryGetProperty("contact-info", out var ci) ? (ci.GetString() ?? string.Empty) : string.Empty,
            ReportId = root.GetProperty("report-id").GetString() ?? string.Empty
        };

        var range = root.GetProperty("date-range");
        report.RangeBeginUtc = ParseDateTimeOffset(range.GetProperty("start-datetime").GetString());
        report.RangeEndUtc = ParseDateTimeOffset(range.GetProperty("end-datetime").GetString());

        var policies = root.GetProperty("policies");
        foreach (var policy in policies.EnumerateArray())
        {
            var pol = policy.GetProperty("policy");
            var sum = policy.GetProperty("summary");

            var entry = new TlsRptPolicyResult
            {
                Policy = new TlsRptPolicy
                {
                    PolicyType = pol.GetProperty("policy-type").GetString() ?? string.Empty,
                    MxHost = pol.GetProperty("mx-host").GetString() ?? string.Empty,
                    PolicyDomain = pol.TryGetProperty("policy-domain", out var pd) ? pd.GetString() : null,
                    PolicyStrings = ReadStringArray(pol, "policy-string")
                },
                Summary = new TlsRptPolicySummary
                {
                    SuccessfulSessionCount = sum.GetProperty("total-successful-session-count").GetInt32(),
                    FailedSessionCount = sum.GetProperty("total-failure-session-count").GetInt32()
                }
            };

            if (policy.TryGetProperty("failure-details", out var details) && details.ValueKind == JsonValueKind.Array)
            {
                foreach (var fd in details.EnumerateArray())
                {
                    entry.FailureDetails.Add(new TlsRptFailureDetail
                    {
                        ResultType = fd.TryGetProperty("result-type", out var rt) ? (rt.GetString() ?? "unknown") : "unknown",
                        FailedSessionCount = fd.TryGetProperty("failed-session-count", out var fc) ? fc.GetInt32() : 0,
                        SendingMtaIp = fd.TryGetProperty("sending-mta-ip", out var ip) ? ip.GetString() : null,
                        ReceivingMxHostname = fd.TryGetProperty("receiving-mx-hostname", out var mxh) ? mxh.GetString() : null,
                        ReceivingMxHelo = fd.TryGetProperty("receiving-mx-helo", out var helo) ? helo.GetString() : null,
                        AdditionalInformation = fd.TryGetProperty("additional-information", out var ai) ? ai.GetString() : null
                    });
                }
            }

            report.Policies.Add(entry);
        }

        return report;
    }

    private static void CopyToWithLimit(Stream source, Stream destination, long maxBytes)
    {
        if (maxBytes <= 0)
        {
            source.CopyTo(destination);
            return;
        }

        var buf = new byte[81920];
        long total = 0;
        int read;
        while ((read = source.Read(buf, 0, buf.Length)) > 0)
        {
            total += read;
            if (total > maxBytes)
            {
                throw new IOException($"Stream exceeds max size {maxBytes} bytes.");
            }
            destination.Write(buf, 0, read);
        }
    }

    private static void ValidateSchema(JsonElement root)
    {
        if (!root.TryGetProperty("organization-name", out _))
        {
            throw new FormatException("Missing organization-name field.");
        }

        if (!root.TryGetProperty("date-range", out var range)
            || !range.TryGetProperty("start-datetime", out _)
            || !range.TryGetProperty("end-datetime", out _))
        {
            throw new FormatException("Missing date-range fields.");
        }

        if (!root.TryGetProperty("report-id", out _))
        {
            throw new FormatException("Missing report-id field.");
        }

        if (!root.TryGetProperty("policies", out var policies) || policies.ValueKind != JsonValueKind.Array)
        {
            throw new FormatException("Missing policies array.");
        }

        foreach (var policy in policies.EnumerateArray())
        {
            if (!policy.TryGetProperty("policy", out var pol)
                || !pol.TryGetProperty("policy-type", out _)
                || !pol.TryGetProperty("mx-host", out _))
            {
                throw new FormatException("Invalid policy entry.");
            }

            if (!policy.TryGetProperty("summary", out var summary)
                || !summary.TryGetProperty("total-successful-session-count", out _)
                || !summary.TryGetProperty("total-failure-session-count", out _))
            {
                throw new FormatException("Invalid summary entry.");
            }
        }
    }

    private static DateTimeOffset ParseDateTimeOffset(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new FormatException("Invalid date-range: missing datetime.");
        }

        if (!DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dto))
        {
            throw new FormatException($"Invalid datetime format: '{text}'.");
        }

        return dto;
    }

    private static List<string> ReadStringArray(JsonElement obj, string propertyName)
    {
        if (!obj.TryGetProperty(propertyName, out var a) || a.ValueKind != JsonValueKind.Array)
        {
            return new List<string>();
        }

        var list = new List<string>();
        foreach (var item in a.EnumerateArray())
        {
            var s = item.GetString();
            if (!string.IsNullOrWhiteSpace(s))
            {
                list.Add(s!);
            }
        }
        return list;
    }
}

public sealed class TlsRptReport
{
    public string OrganizationName { get; set; } = string.Empty;
    public string ContactInfo { get; set; } = string.Empty;
    public string ReportId { get; set; } = string.Empty;
    public DateTimeOffset RangeBeginUtc { get; set; }
    public DateTimeOffset RangeEndUtc { get; set; }
    public List<TlsRptPolicyResult> Policies { get; } = new();
}

public sealed class TlsRptPolicyResult
{
    public TlsRptPolicy Policy { get; set; } = new();
    public TlsRptPolicySummary Summary { get; set; } = new();
    public List<TlsRptFailureDetail> FailureDetails { get; } = new();
}

public sealed class TlsRptPolicy
{
    public string PolicyType { get; set; } = string.Empty;
    public string MxHost { get; set; } = string.Empty;
    public string? PolicyDomain { get; set; }
    public List<string> PolicyStrings { get; set; } = new();
}

public sealed class TlsRptPolicySummary
{
    public int SuccessfulSessionCount { get; set; }
    public int FailedSessionCount { get; set; }
}

public sealed class TlsRptFailureDetail
{
    public string ResultType { get; set; } = "unknown";
    public int FailedSessionCount { get; set; }
    public string? SendingMtaIp { get; set; }
    public string? ReceivingMxHostname { get; set; }
    public string? ReceivingMxHelo { get; set; }
    public string? AdditionalInformation { get; set; }
}

