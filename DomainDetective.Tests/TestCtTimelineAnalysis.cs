using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestCtTimelineAnalysis
{
    [Fact]
    public async Task AggregatesCtTimelineAndRecentCertificates()
    {
        var now = DateTimeOffset.UtcNow;
        var entry1 = now.AddDays(-1);
        var entry2 = now.AddDays(-20);
        var entry3 = now.AddDays(-40);
        var entryDup = now.AddDays(-2);

        var json = $@"
[
  {{ ""id"": 1001, ""issuer_name"": ""Issuer A"", ""entry_timestamp"": ""{entry1.ToString("O", CultureInfo.InvariantCulture)}"", ""not_before"": ""{now.AddDays(-10).ToString("O", CultureInfo.InvariantCulture)}"", ""not_after"": ""{now.AddDays(10).ToString("O", CultureInfo.InvariantCulture)}"", ""common_name"": ""example.com"", ""name_value"": ""example.com"" }},
  {{ ""id"": 1002, ""issuer_name"": ""Issuer A"", ""entry_timestamp"": ""{entry2.ToString("O", CultureInfo.InvariantCulture)}"", ""not_before"": ""{now.AddDays(-100).ToString("O", CultureInfo.InvariantCulture)}"", ""not_after"": ""{now.AddDays(-50).ToString("O", CultureInfo.InvariantCulture)}"", ""common_name"": ""example.com"", ""name_value"": ""example.com"" }},
  {{ ""id"": 1003, ""issuer_name"": ""Issuer B"", ""entry_timestamp"": ""{entry3.ToString("O", CultureInfo.InvariantCulture)}"", ""not_before"": ""{now.AddDays(50).ToString("O", CultureInfo.InvariantCulture)}"", ""not_after"": ""{now.AddDays(100).ToString("O", CultureInfo.InvariantCulture)}"", ""common_name"": ""*.example.com"", ""name_value"": ""*.example.com\nexample.com"" }},
  {{ ""id"": 1001, ""issuer_name"": ""Issuer A"", ""entry_timestamp"": ""{entryDup.ToString("O", CultureInfo.InvariantCulture)}"", ""not_before"": ""{now.AddDays(-10).ToString("O", CultureInfo.InvariantCulture)}"", ""not_after"": ""{now.AddDays(10).ToString("O", CultureInfo.InvariantCulture)}"", ""common_name"": ""example.com"", ""name_value"": ""example.com"" }}
]";

        var analysis = new CertificateTransparencyTimelineAnalysis
        {
            CrtShExactUrlTemplate = string.Empty,
            QueryOverride = (_, _) => Task.FromResult(json)
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Equal(4, analysis.CertificateObservationCount);
        Assert.Equal(3, analysis.UniqueCertificateCount);
        Assert.Equal(entry3, analysis.FirstSeenUtc);
        Assert.Equal(entry1, analysis.LastSeenUtc);

        Assert.Equal(2, analysis.DistinctIssuerCount);
        Assert.True(analysis.IssuerCounts.TryGetValue("Issuer A", out var issuerACount));
        Assert.Equal(2, issuerACount);
        Assert.True(analysis.IssuerCounts.TryGetValue("Issuer B", out var issuerBCount));
        Assert.Equal(1, issuerBCount);

        Assert.Equal(1, analysis.ActiveCertificateCount);
        Assert.Equal(1, analysis.ExpiredCertificateCount);
        Assert.Equal(1, analysis.NotYetValidCertificateCount);
        Assert.Equal(1, analysis.WildcardCertificateCount);
        Assert.Equal(1, analysis.IssuedLast7Days);
        Assert.Equal(2, analysis.IssuedLast30Days);

        var expectedBuckets = new Dictionary<string, (int Certificates, int Issuers)>(StringComparer.OrdinalIgnoreCase);
        var certRows = new[]
        {
            // Certificate 1001 dates from its earlier duplicate entry.
            new { Issuer = "Issuer A", Entry = entryDup },
            new { Issuer = "Issuer A", Entry = entry2 },
            new { Issuer = "Issuer B", Entry = entry3 }
        };

        foreach (var row in certRows)
        {
            var key = row.Entry.ToString("yyyy-MM", CultureInfo.InvariantCulture);
            if (!expectedBuckets.TryGetValue(key, out var agg))
            {
                agg = (0, 0);
            }
            agg.Certificates++;
            var issuers = certRows
                .Where(r => r.Entry.ToString("yyyy-MM", CultureInfo.InvariantCulture).Equals(key, StringComparison.OrdinalIgnoreCase))
                .Select(r => r.Issuer)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
            expectedBuckets[key] = (agg.Certificates, issuers);
        }

        Assert.Equal(expectedBuckets.Count, analysis.Timeline.Count);
        foreach (var kv in expectedBuckets)
        {
            var bucket = analysis.Timeline.Single(b => b.ToString().Equals(kv.Key, StringComparison.OrdinalIgnoreCase));
            Assert.Equal(kv.Value.Certificates, bucket.UniqueCertificates);
            Assert.Equal(kv.Value.Issuers, bucket.DistinctIssuers);
        }

        Assert.Equal(3, analysis.RecentCertificates.Count);
        Assert.Equal("Issuer A", analysis.RecentCertificates[0].IssuerName);
        Assert.Equal(CtCertificateValidityStatus.Active, analysis.RecentCertificates[0].ValidityStatus);
    }

    // crt.sh rows for one real issuance: precertificate 29761450106 and its final certificate 29974950817.
    // crt.sh gives them different ids; they share the issuer and serial number.
    private const string RealPrecertificateRow = @"{""issuer_ca_id"":286236,""issuer_name"":""C=US, O=Google Trust Services, CN=WE1"",""common_name"":""e6.c.lencr.org"",""name_value"":""e6.c.lencr.org"",""id"":29761450106,""not_before"":""2026-10-03T22:43:41"",""not_after"":""2027-01-01T23:43:37"",""serial_number"":""4a053753581caee2134f96e3eb81d281"",""result_count"":2}";
    private const string RealFinalCertificateRow = @"{""issuer_ca_id"":286236,""issuer_name"":""C=US, O=Google Trust Services, CN=WE1"",""common_name"":""e6.c.lencr.org"",""name_value"":""e6.c.lencr.org"",""id"":29974950817,""not_before"":""2026-10-03T22:43:41"",""not_after"":""2027-01-01T23:43:37"",""serial_number"":""4a053753581caee2134f96e3eb81d281"",""result_count"":2}";

    [Fact]
    public async Task CountsPrecertificateAndFinalCertificateAsOneIssuance()
    {
        // Both the subdomain and the exact-name query return the same two rows.
        var json = "[" + RealPrecertificateRow + "," + RealFinalCertificateRow + "]";
        var analysis = new CertificateTransparencyTimelineAnalysis
        {
            QueryOverride = (_, _) => Task.FromResult(json)
        };

        await analysis.AnalyzeAsync("e6.c.lencr.org", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Equal(4, analysis.CertificateObservationCount);
        Assert.Equal(1, analysis.UniqueCertificateCount);
        var issuer = Assert.Single(analysis.IssuerCounts);
        Assert.Equal(1, issuer.Value);
        Assert.Equal(1, analysis.ActiveCertificateCount + analysis.ExpiredCertificateCount + analysis.NotYetValidCertificateCount);
        Assert.Equal(1, Assert.Single(analysis.Timeline).UniqueCertificates);

        var sample = Assert.Single(analysis.RecentCertificates);
        Assert.Equal(new[] { "29761450106", "29974950817" }, sample.EntryIds);
    }

    [Fact]
    public async Task UniqueCertificateCapStillMergesEntriesOfRetainedIssuances()
    {
        // The final certificate arrives first; another issuance between it and its precertificate hits the cap.
        const string otherRow = @"{""issuer_name"":""C=US, O=Example CA, CN=R1"",""common_name"":""www.e6.c.lencr.org"",""id"":1,""not_before"":""2026-10-01T00:00:00"",""not_after"":""2026-12-30T00:00:00"",""serial_number"":""01""}";
        var json = "[" + RealFinalCertificateRow + "," + otherRow + "," + RealPrecertificateRow + "]";
        var analysis = new CertificateTransparencyTimelineAnalysis
        {
            MaxUniqueCertificates = 1,
            QueryOverride = (_, _) => Task.FromResult(json)
        };

        await analysis.AnalyzeAsync("e6.c.lencr.org", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.ResultsCapped);
        Assert.Contains(analysis.Assessments, a => a.Code == CtTimelineCodes.ResultsCapped);
        Assert.Equal(6, analysis.CertificateObservationCount);
        Assert.Equal(1, analysis.UniqueCertificateCount);
        var sample = Assert.Single(analysis.RecentCertificates);
        Assert.Equal(new[] { "29974950817", "29761450106" }, sample.EntryIds);
    }

    [Fact]
    public async Task CapsCtRowsAndProducesCappedAssessment()
    {
        var now = DateTimeOffset.UtcNow;
        var json = $@"
[
  {{ ""id"": 1, ""issuer_name"": ""Issuer A"", ""entry_timestamp"": ""{now.AddDays(-1).ToString("O", CultureInfo.InvariantCulture)}"", ""not_before"": ""{now.AddDays(-10).ToString("O", CultureInfo.InvariantCulture)}"", ""not_after"": ""{now.AddDays(10).ToString("O", CultureInfo.InvariantCulture)}"", ""common_name"": ""example.com"", ""name_value"": ""example.com"" }},
  {{ ""id"": 2, ""issuer_name"": ""Issuer B"", ""entry_timestamp"": ""{now.AddDays(-2).ToString("O", CultureInfo.InvariantCulture)}"", ""not_before"": ""{now.AddDays(-10).ToString("O", CultureInfo.InvariantCulture)}"", ""not_after"": ""{now.AddDays(10).ToString("O", CultureInfo.InvariantCulture)}"", ""common_name"": ""example.com"", ""name_value"": ""example.com"" }}
]";

        var analysis = new CertificateTransparencyTimelineAnalysis
        {
            CrtShExactUrlTemplate = string.Empty,
            MaxCtRowsToProcess = 1,
            QueryOverride = (_, _) => Task.FromResult(json)
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.True(analysis.ResultsCapped);
        Assert.Equal(1, analysis.CertificateObservationCount);
        Assert.Contains(analysis.Assessments, a => a.Code == CtTimelineCodes.ResultsCapped);
    }

    [Fact]
    public async Task FallsBackToCertSpotterWhenCrtShFails()
    {
        var now = DateTimeOffset.UtcNow;
        var certSpotterJson = $@"
[
  {{ ""id"": ""abc-123"", ""dns_names"": [""example.com"", ""www.example.com""], ""not_before"": ""{now.AddDays(-2).ToString("O", CultureInfo.InvariantCulture)}"", ""not_after"": ""{now.AddDays(90).ToString("O", CultureInfo.InvariantCulture)}"", ""revoked"": false }}
]";

        var analysis = new CertificateTransparencyTimelineAnalysis
        {
            QueryOverride = (url, _) =>
            {
                if (url.Contains("crt.sh", StringComparison.OrdinalIgnoreCase))
                {
                    throw new HttpRequestException("Simulated crt.sh outage.");
                }

                return Task.FromResult(certSpotterJson);
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Equal(1, analysis.CertificateObservationCount);
        Assert.Equal(1, analysis.UniqueCertificateCount);
        Assert.Equal(1, analysis.ActiveCertificateCount);
        Assert.Equal(0, analysis.DistinctIssuerCount);
        Assert.Single(analysis.RecentCertificates);
        Assert.Equal("example.com", analysis.RecentCertificates[0].CommonName);
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == CtTimelineCodes.QueryFailed);
    }

    [Fact]
    public async Task FallsBackToCertSpotterWhenPrimaryPayloadIsMalformed()
    {
        var now = DateTimeOffset.UtcNow;
        var certSpotterJson = $@"
[
  {{ ""id"": ""abc-456"", ""dns_names"": [""example.com""], ""not_before"": ""{now.AddDays(-5).ToString("O", CultureInfo.InvariantCulture)}"", ""not_after"": ""{now.AddDays(120).ToString("O", CultureInfo.InvariantCulture)}"", ""revoked"": false }}
]";

        var analysis = new CertificateTransparencyTimelineAnalysis
        {
            QueryOverride = (url, _) =>
            {
                if (url.Contains("crt.sh", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(@"{ ""status"": ""rate_limited"" }");
                }

                return Task.FromResult(certSpotterJson);
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Equal(1, analysis.CertificateObservationCount);
        Assert.Single(analysis.RecentCertificates);
    }
}
