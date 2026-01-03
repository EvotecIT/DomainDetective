using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
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
            new { Issuer = "Issuer A", Entry = entry1 },
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
}

