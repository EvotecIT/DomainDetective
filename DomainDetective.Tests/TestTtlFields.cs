using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Reports;
using DomainDetective.Views;
using DnsClientX;
using Xunit;

namespace DomainDetective.Tests;

public class TestTtlFields
{
    [Fact]
    public async Task DmarcAnalysisCapturesTtls()
    {
        var answers = new[]
        {
            new DnsAnswer { TTL = 300, DataRaw = "v=DMARC1; p=none", Type = DnsRecordType.TXT },
            new DnsAnswer { TTL = 900, DataRaw = "v=DMARC1; p=reject", Type = DnsRecordType.TXT }
        };

        var analysis = new DmarcAnalysis();
        await analysis.AnalyzeDmarcRecords(answers, new InternalLogger());

        Assert.Equal(new[] { 300, 900 }, analysis.DnsRecordTtls);
        Assert.Equal(300, analysis.DnsRecordTtl);
    }

    [Fact]
    public async Task DmarcTtlIgnoresCnameHops()
    {
        var answers = new[]
        {
            new DnsAnswer { TTL = 60, DataRaw = "cname.example.net", Type = DnsRecordType.CNAME },
            new DnsAnswer { TTL = 86400, DataRaw = "v=DMARC1; p=reject", Type = DnsRecordType.TXT }
        };

        var analysis = new DmarcAnalysis();
        await analysis.AnalyzeDmarcRecords(answers, new InternalLogger());

        Assert.Equal(new[] { 86400 }, analysis.DnsRecordTtls);
        Assert.Equal(86400, analysis.DnsRecordTtl);
    }

    [Fact]
    public async Task SpfAnalysisCapturesTtls()
    {
        var answers = new[]
        {
            new DnsAnswer { TTL = 120, DataRaw = "v=spf1 -all", Type = DnsRecordType.TXT }
        };

        var analysis = new SpfAnalysis { DnsConfiguration = new DnsConfiguration() };
        await analysis.AnalyzeSpfRecords(answers, new InternalLogger());

        Assert.Equal(new[] { 120 }, analysis.DnsRecordTtls);
        Assert.Equal(120, analysis.DnsRecordTtl);
    }

    [Fact]
    public async Task DkimAnalysisCapturesTtls()
    {
        var answers = new[]
        {
            new DnsAnswer { TTL = 600, DataRaw = "v=DKIM1; p=AAA", Name = "s1._domainkey.example.com", Type = DnsRecordType.TXT },
            new DnsAnswer { TTL = 450, DataRaw = "v=DKIM1; p=BBB", Name = "s1._domainkey.example.com", Type = DnsRecordType.TXT }
        };

        var analysis = new DkimAnalysis();
        await analysis.AnalyzeDkimRecords("s1", answers, new InternalLogger());

        var result = analysis.AnalysisResults["s1"];
        Assert.Equal(new[] { 600, 450 }, result.Ttls);
        Assert.Equal(450, result.Ttl);
    }

    [Fact]
    public async Task MtastsAnalysisCapturesDnsTtls()
    {
        var answers = new[]
        {
            new DnsAnswer { TTL = 7200, DataRaw = "v=STSv1; id=20240101", Type = DnsRecordType.TXT }
        };

        var analysis = new MTASTSAnalysis
        {
            QueryDnsOverride = (_, _) => Task.FromResult(answers),
            PolicyUrlOverride = "http://127.0.0.1:0/.well-known/mta-sts.txt"
        };

        await analysis.AnalyzePolicy("example.com", new InternalLogger());

        Assert.Equal(new[] { 7200 }, analysis.DnsRecordTtls);
        Assert.Equal(7200, analysis.DnsRecordTtl);
    }

    [Fact]
    public async Task MtastsTtlIgnoresCnameHops()
    {
        var answers = new[]
        {
            new DnsAnswer { TTL = 60, DataRaw = "mta-sts.example.net", Type = DnsRecordType.CNAME },
            new DnsAnswer { TTL = 86400, DataRaw = "v=STSv1; id=20240101", Type = DnsRecordType.TXT }
        };

        var analysis = new MTASTSAnalysis
        {
            QueryDnsOverride = (_, _) => Task.FromResult(answers),
            PolicyUrlOverride = "http://127.0.0.1:0/.well-known/mta-sts.txt"
        };

        await analysis.AnalyzePolicy("example.com", new InternalLogger());

        Assert.Equal(new[] { 86400 }, analysis.DnsRecordTtls);
        Assert.Equal(86400, analysis.DnsRecordTtl);
    }

    [Fact]
    public async Task TlsRptAnalysisCapturesDnsTtls()
    {
        var answers = new[]
        {
            new DnsAnswer { TTL = 1800, DataRaw = "v=TLSRPTv1; rua=mailto:reports@example.com", Type = DnsRecordType.TXT },
            new DnsAnswer { TTL = 900, DataRaw = "v=TLSRPTv1; rua=mailto:reports@example.com", Type = DnsRecordType.TXT }
        };

        var analysis = new TLSRPTAnalysis();
        await analysis.AnalyzeTlsRptRecords(answers, new InternalLogger());

        Assert.Equal(new[] { 1800, 900 }, analysis.DnsRecordTtls);
        Assert.Equal(900, analysis.DnsRecordTtl);
    }

    [Fact]
    public async Task TlsRptTtlIgnoresCnameHops()
    {
        var answers = new[]
        {
            new DnsAnswer { TTL = 60, DataRaw = "tlsrpt.example.net", Type = DnsRecordType.CNAME },
            new DnsAnswer { TTL = 86400, DataRaw = "v=TLSRPTv1; rua=mailto:reports@example.com", Type = DnsRecordType.TXT }
        };

        var analysis = new TLSRPTAnalysis();
        await analysis.AnalyzeTlsRptRecords(answers, new InternalLogger());

        Assert.Equal(new[] { 86400 }, analysis.DnsRecordTtls);
        Assert.Equal(86400, analysis.DnsRecordTtl);
    }

    [Fact]
    public async Task MxAnalysisCapturesDnsTtls()
    {
        var answers = new[]
        {
            new DnsAnswer { TTL = 500, Data = "10 mail.example.com", Type = DnsRecordType.MX },
            new DnsAnswer { TTL = 400, Data = "20 backup.example.com", Type = DnsRecordType.MX }
        };

        var analysis = new MXAnalysis
        {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>())
        };

        await analysis.AnalyzeMxRecords(answers, new InternalLogger());

        Assert.Equal(new[] { 500, 400 }, analysis.MxRecordTtls);
        Assert.Equal(400, analysis.MinMxTtl);
    }

    [Fact]
    public void MxConverterSurfacesTtls()
    {
        var analysis = new MXAnalysis
        {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>())
        };

        var answers = new[]
        {
            new DnsAnswer { TTL = 250, Data = "10 mail.example.com", Type = DnsRecordType.MX }
        };

        analysis.AnalyzeMxRecords(answers, new InternalLogger()).GetAwaiter().GetResult();

        var view = Converters.Convert(analysis);
        Assert.Equal(250, view.MxRecordTtl);
        Assert.True(view.MxRecordTtls.SequenceEqual(new[] { 250 }));
    }

    [Fact]
    public void TtlViewPrefersAuthoritativeValuesWhenPresent()
    {
        static void SetProperty<T>(object target, string name, T value)
        {
            var prop = target.GetType().GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            Assert.NotNull(prop);
            prop!.SetValue(target, value);
        }

        var analysis = new DnsTtlAnalysis { Subject = "example.com" };
        SetProperty(analysis, nameof(DnsTtlAnalysis.SoaTtl), 600);
        SetProperty(analysis, nameof(DnsTtlAnalysis.AuthoritativeSoaTtl), 3600);
        SetProperty(analysis, nameof(DnsTtlAnalysis.ATtls), new[] { 300 });
        SetProperty(analysis, nameof(DnsTtlAnalysis.AuthoritativeATtls), new[] { 1200 });
        SetProperty(analysis, nameof(DnsTtlAnalysis.DmarcTxtTtls), new[] { 3600 });
        SetProperty(analysis, nameof(DnsTtlAnalysis.AuthoritativeDmarcTxtTtls), new[] { 86400 });
        SetProperty(analysis, nameof(DnsTtlAnalysis.MtastsTxtTtls), new[] { 1800 });
        SetProperty(analysis, nameof(DnsTtlAnalysis.AuthoritativeMtastsTxtTtls), new[] { 7200 });
        SetProperty(analysis, nameof(DnsTtlAnalysis.TlsRptTxtTtls), new[] { 900 });
        SetProperty(analysis, nameof(DnsTtlAnalysis.AuthoritativeTlsRptTxtTtls), new[] { 21600 });
        SetProperty(analysis, nameof(DnsTtlAnalysis.DkimTxtTtls), new Dictionary<string, IReadOnlyList<int>>
        {
            ["s1._domainkey.example.com"] = new[] { 300 }
        });
        SetProperty(analysis, nameof(DnsTtlAnalysis.AuthoritativeDkimTxtTtls), new Dictionary<string, IReadOnlyList<int>>(StringComparer.OrdinalIgnoreCase)
        {
            ["s1._domainkey.example.com"] = new[] { 172800 }
        });

        var view = Converters.Convert(analysis);

        Assert.Equal(3600, view.SoaTtl);
        Assert.Equal(new[] { 1200 }, view.ATtls);
        Assert.Equal(new[] { 86400 }, view.DmarcTxtTtls);
        Assert.Equal(new[] { 7200 }, view.MtastsTxtTtls);
        Assert.Equal(new[] { 21600 }, view.TlsRptTxtTtls);
        Assert.True(view.DkimTxtTtls.TryGetValue("s1._domainkey.example.com", out var ttls));
        Assert.Equal(172800, ttls.Min());
    }

    [Fact]
    public void DkimSectionUsesAuthoritativeTtlWhenAvailable()
    {
        var dkim = new[]
        {
            new DkimRecordInfo
            {
                Selector = "s1",
                Subject = "example.com",
                Name = "s1._domainkey.example.com",
                DkimRecord = "v=DKIM1; p=AAA",
                Assessments = Array.Empty<Assessment>()
            }
        };
        var ttl = new TtlInfo
        {
            DkimTxtTtls = new Dictionary<string, IReadOnlyList<int>>
            {
                ["s1._domainkey.example.com"] = new[] { 300 }
            },
            AuthoritativeDkimTxtTtls = new Dictionary<string, IReadOnlyList<int>>
            {
                ["s1._domainkey.example.com"] = new[] { 86400 }
            }
        };

        var section = SectionProjectors.BuildDkim(dkim, ttl);

        Assert.NotNull(section);
        Assert.Single(section!.Rows);
        Assert.Equal(86400, section.Rows[0].TtlSeconds);
    }
}
