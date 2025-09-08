using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestViewSnapshots
{
    [Fact]
    public async Task Spf_ViewCountsAndReferences_PositivePartitioning()
    {
        var logger = new InternalLogger();
        var analysis = new SpfAnalysis { Subject = "example.com", DnsConfiguration = new DnsConfiguration() };
        // Provide a simple SPF record that should produce info-level positives (present, starts v1, -all, lookups within limit)
        await analysis.AnalyzeSpfRecords(new[] { new DnsAnswer { DataRaw = "v=spf1 -all", Type = DnsRecordType.TXT } }, logger);
        var view = Converters.Convert(analysis);

        // Counts
        Assert.Equal("OK", view.Status);
        Assert.Equal(0, view.WarningCount);
        Assert.Equal(0, view.ErrorCount);

        // Partitioning: recommendations exclude info; positives include info
        Assert.Empty(view.Recommendations); // no warnings/errors
        var posCodes = view.Positives.Select(p => p.Code).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Contains(SpfCodes.Present, posCodes);
        Assert.Contains(SpfCodes.StartsV1, posCodes);
        Assert.Contains(SpfCodes.AllEnforced, posCodes);

        // References populated (RFC 7208)
        Assert.Contains(view.References, r => r.IndexOf("rfc7208", StringComparison.OrdinalIgnoreCase) >= 0);
    }

    [Fact]
    public async Task Dmarc_ViewCountsAndReferences_PositivePartitioning()
    {
        var answers = new[] { new DnsAnswer { DataRaw = "v=DMARC1; p=none; rua=mailto:test@example.com; ruf=http://bad.example.com", Type = DnsRecordType.TXT } };
        var logger = new InternalLogger();
        var analysis = new DmarcAnalysis();
        var psl = PublicSuffixList.Load(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "public_suffix_list.dat"));
        await analysis.AnalyzeDmarcRecords(answers, logger, "example.com", psl.GetRegistrableDomain);
        var view = Converters.Convert(analysis);

        Assert.Equal("Warning", view.Status);
        Assert.True(view.WarningCount >= 1);
        Assert.Equal(0, view.ErrorCount);

        var recCodes = view.Recommendations.Select(r => r.Code).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Contains(DmarcCodes.UriInsecure, recCodes);

        var posCodes = view.Positives.Select(p => p.Code).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Contains(DmarcCodes.Present, posCodes);
        Assert.Contains(DmarcCodes.StartsV1, posCodes);

        // References populated due to QueryFailed advice links
        Assert.NotEmpty(view.References);
    }
}
