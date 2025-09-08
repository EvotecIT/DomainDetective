using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestProviderPositives
{
    [Fact]
    public async Task Dmarc_EmitsInfoPositives_AndRecommendationsExcludeInfo()
    {
        var record = new[]
        {
            // Intentionally use insecure ruf HTTP to produce a Warning (UriInsecure)
            new DnsAnswer { DataRaw = "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s; rua=mailto:reports@example.com; ruf=http://bad.example.com", Type = DnsRecordType.TXT }
        };
        var logger = new InternalLogger();
        var analysis = new DmarcAnalysis();
        var psl = PublicSuffixList.Load(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "public_suffix_list.dat"));
        await analysis.AnalyzeDmarcRecords(record, logger, "example.com", psl.GetRegistrableDomain);

        var view = Converters.Convert(analysis);

        // Status counts reflect the warning
        Assert.Equal("Warning", view.Status);
        Assert.True(view.WarningCount >= 1);
        Assert.Equal(0, view.ErrorCount);

        // Recommendations should include non-info only (e.g., UriInsecure)
        Assert.Contains(view.Recommendations, r => r.Code == DmarcCodes.UriInsecure);

        // Positives include only Info-level posture signals
        var posCodes = view.Positives.Select(p => p.Code).ToList();
        Assert.Contains(DmarcCodes.Present, posCodes);
        Assert.Contains(DmarcCodes.StartsV1, posCodes);
        Assert.Contains(DmarcCodes.PolicyReject, posCodes);
        Assert.Contains(DmarcCodes.RuaPresent, posCodes);
        Assert.Contains(DmarcCodes.RufPresent, posCodes);
        Assert.Contains(DmarcCodes.AlignmentStrictDkim, posCodes);
        Assert.Contains(DmarcCodes.AlignmentStrictSpf, posCodes);
        Assert.Contains(DmarcCodes.Percent100, posCodes);

        // Ensure Recommendations exclude Info codes
        var recCodes = view.Recommendations.Select(r => r.Code).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain(DmarcCodes.Present, recCodes);
        Assert.DoesNotContain(DmarcCodes.RuaPresent, recCodes);

        // References populated (from non-info advice mapping)
        Assert.NotEmpty(view.References);
    }

    [Fact]
    public async Task Dkim_EmitsInfoPositives_ForCommonGoodSignals()
    {
        var logger = new InternalLogger();
        var dkim = new DkimAnalysis();
        var answers = new List<DnsAnswer>
        {
            new DnsAnswer { DataRaw = "v=DKIM1; k=rsa; h=sha256; c=relaxed/relaxed; p=AAAAB3NzaC1yc2EAAAADAQABAAABAQ", Type = DnsRecordType.TXT }
        };
        await dkim.AnalyzeDkimRecords("selector1._domainkey.example.com", answers, logger);

        // Check that Info-level positives were produced
        var infoCodes = dkim.Assessments.Where(a => a.Severity == AssessmentSeverity.Info)
            .Select(a => a.Code)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains(DkimCodes.RecordPresent, infoCodes);
        Assert.Contains(DkimCodes.RecordStartsV1, infoCodes);
        Assert.Contains(DkimCodes.KeyTypeValid, infoCodes);
        Assert.Contains(DkimCodes.CanonicalizationValid, infoCodes);
        Assert.Contains(DkimCodes.HashSha256, infoCodes);

        // And that these surface via the view's Positives
        var viewItems = Converters.Convert(dkim).ToList();
        Assert.NotEmpty(viewItems);
        var positives = viewItems.SelectMany(v => v.Positives).Select(p => p.Code).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Contains(DkimCodes.KeyTypeValid, positives);
        Assert.Contains(DkimCodes.CanonicalizationValid, positives);
        Assert.Contains(DkimCodes.HashSha256, positives);
    }
}
