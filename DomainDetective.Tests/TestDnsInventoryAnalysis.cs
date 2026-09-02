using DnsClientX;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Providers.Dns;
using DomainDetective.Providers.Email;

namespace DomainDetective.Tests;

public class TestDnsInventoryAnalysis
{
    [Fact]
    public async Task CapturesAnswersAndAuthorities()
    {
        var analysis = new DnsInventoryAnalysis
        {
            IncludeAuthorities = true,
            IncludeAdditional = false,
            QueryConcurrency = 2,
            QueryOverride = (_, type, _) =>
            {
                var resp = new DnsResponse { Status = DnsResponseCode.NoError };

                if (type == DnsRecordType.A)
                {
                    resp.Answers = new[]
                    {
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.A, TTL = 300, DataRaw = "192.0.2.1" }
                    };
                    resp.Authorities = new[]
                    {
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.SOA, TTL = 3600, DataRaw = "ns1.example.com hostmaster.example.com 1 7200 900 1209600 86400" }
                    };
                }
                else if (type == DnsRecordType.AAAA)
                {
                    resp.Answers = new[]
                    {
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.AAAA, TTL = 300, DataRaw = "2001:db8::1" }
                    };
                }
                else if (type == DnsRecordType.NS)
                {
                    resp.Answers = new[]
                    {
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.NS, TTL = 300, DataRaw = "gwen.ns.cloudflare.com." }
                    };
                }
                else if (type == DnsRecordType.CNAME)
                {
                    resp.Answers = new[]
                    {
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.CNAME, TTL = 300, DataRaw = "example.cloudflare.net." }
                    };
                }
                else if (type == DnsRecordType.MX)
                {
                    resp.Answers = new[]
                    {
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.MX, TTL = 300, DataRaw = "10 example-com.mail.protection.outlook.com." }
                    };
                }
                else if (type == DnsRecordType.TXT)
                {
                    resp.Answers = new[]
                    {
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.TXT, TTL = 60, DataRaw = "\"v=spf1 include:spf.protection.outlook.com -all\"" },
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.TXT, TTL = 60, DataRaw = "\"google-site-verification=abc\"" }
                    };
                }
                else if (type == DnsRecordType.CAA)
                {
                    resp.Answers = new[]
                    {
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.CAA, TTL = 3600, DataRaw = "0 issue \"letsencrypt.org\"" },
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.CAA, TTL = 3600, DataRaw = "0 issue \"pki.goog\"" }
                    };
                }

                return Task.FromResult(resp);
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Equal(8, analysis.RecordTypesQueried);
        Assert.Equal(0, analysis.RecordTypesFailed);
        Assert.Equal(10, analysis.TotalRecords);
        Assert.Equal(DnsProvider.Cloudflare, analysis.Provider);
        Assert.Equal(MailProviderKind.Microsoft365, analysis.MailProvider);
        Assert.Equal(DnsCnameTargetProvider.Cloudflare, analysis.CnameTargetProvider);
        Assert.True(analysis.CnameTargetFlags.HasFlag(DnsCnameTargetFlags.FlatteningService));
        Assert.True(analysis.TxtSignals.HasFlag(DnsTxtSignals.Spf));
        Assert.True(analysis.TxtSignals.HasFlag(DnsTxtSignals.GoogleSiteVerification));
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "dns-provider-cloudflare" && app.Category == DetectedDnsAppCategory.DnsHosting && app.Confidence == Microsoft365DetectionConfidence.Strong);
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "cname-target-cloudflare" && app.Category == DetectedDnsAppCategory.CDN && app.EvidenceKind == DetectedDnsAppEvidenceKind.CnameRecord && app.Confidence == Microsoft365DetectionConfidence.Strong);
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "mail-provider-microsoft365" && app.Category == DetectedDnsAppCategory.Productivity && app.Confidence == Microsoft365DetectionConfidence.Strong);
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "google-site-verification" && app.EvidenceKind == DetectedDnsAppEvidenceKind.TxtRecord && app.Confidence == Microsoft365DetectionConfidence.Moderate);
        Assert.True(analysis.CaaIssuers.HasFlag(DnsCaaIssuers.LetsEncrypt));
        Assert.True(analysis.CaaIssuers.HasFlag(DnsCaaIssuers.GoogleTrustServices));
        Assert.Contains(analysis.Assessments, assessment =>
            assessment.Code == DnsInventoryCodes.TxtSignalsExposed &&
            assessment.Message.Contains("Google Site Verification", StringComparison.OrdinalIgnoreCase));

        Assert.Contains(
            analysis.Queries.SelectMany(q => q.Records),
            r => r.Section == DnsInventorySection.Authority && r.Type == DnsRecordType.SOA);
    }

    [Fact]
    public async Task FailedTypeIsCountedAndProducesAssessment()
    {
        var analysis = new DnsInventoryAnalysis
        {
            IncludeAuthorities = false,
            QueryOverride = (_, type, _) =>
            {
                if (type == DnsRecordType.CAA)
                {
                    throw new InvalidOperationException("boom");
                }
                return Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Equal(1, analysis.RecordTypesFailed);
        Assert.Contains(analysis.Assessments, a => a.Code == DnsInventoryCodes.QueryFailed);
    }

    [Fact]
    public async Task CapsRecordsPerSection()
    {
        var analysis = new DnsInventoryAnalysis
        {
            IncludeAuthorities = false,
            MaxRecordsPerSection = 2,
            QueryOverride = (_, type, _) =>
            {
                var resp = new DnsResponse { Status = DnsResponseCode.NoError };
                if (type == DnsRecordType.TXT)
                {
                    resp.Answers = new[]
                    {
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.TXT, TTL = 60, DataRaw = "\"a\"" },
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.TXT, TTL = 60, DataRaw = "\"b\"" },
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.TXT, TTL = 60, DataRaw = "\"c\"" }
                    };
                }
                return Task.FromResult(resp);
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        var txt = analysis.Queries.Single(q => q.RecordType == DnsRecordType.TXT);
        Assert.Equal(2, txt.Records.Count(r => r.Section == DnsInventorySection.Answer));
    }

    [Fact]
    public void CnameTargetDetectorHonorsDomainBoundaries()
    {
        var a = DnsCnameTargetDetector.Detect("mycloudflare.net");
        Assert.Equal(DnsCnameTargetProvider.Unknown, a.Provider);

        var b = DnsCnameTargetDetector.Detect("demo.cloudflare.net.");
        Assert.Equal(DnsCnameTargetProvider.Cloudflare, b.Provider);
    }

    [Theory]
    [InlineData("tenant.azurefd.net", DnsCnameTargetProvider.Azure, DnsCnameTargetService.AzureFrontDoor)]
    [InlineData("tenant.azureedge.net", DnsCnameTargetProvider.Azure, DnsCnameTargetService.AzureCdn)]
    [InlineData("tenant.trafficmanager.net", DnsCnameTargetProvider.Azure, DnsCnameTargetService.AzureTrafficManager)]
    [InlineData("cdn.perf1.com", DnsCnameTargetProvider.NameShield, DnsCnameTargetService.NameShieldRedirection)]
    public void CnameTargetDetectorDistinguishesManagedServices(
        string target,
        DnsCnameTargetProvider provider,
        DnsCnameTargetService service)
    {
        DnsCnameTargetDetector.Match match = DnsCnameTargetDetector.Detect(target);

        Assert.Equal(provider, match.Provider);
        Assert.Equal(service, match.Service);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CnameInventoryLeavesConflictingOwnerTargetsUnclassified(bool reverseOrder)
    {
        var answers = new[]
        {
            new DnsAnswer { Name = "example.com", Type = DnsRecordType.CNAME, DataRaw = "a.cloudflare.net." },
            new DnsAnswer { Name = "example.com", Type = DnsRecordType.CNAME, DataRaw = "z.azurefd.net." }
        };
        if (reverseOrder)
        {
            Array.Reverse(answers);
        }
        var analysis = new DnsInventoryAnalysis
        {
            IncludeAuthorities = false,
            QueryOverride = (_, type, _) => Task.FromResult(new DnsResponse
            {
                Status = DnsResponseCode.NoError,
                Answers = type == DnsRecordType.CNAME ? answers : Array.Empty<DnsAnswer>()
            })
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.Equal(DnsCnameTargetProvider.Unknown, analysis.CnameTargetProvider);
        Assert.Equal(DnsCnameTargetService.Unknown, analysis.CnameTargetService);
        Assert.Equal(DnsCnameTargetFlags.None, analysis.CnameTargetFlags);
        Assert.DoesNotContain(analysis.DetectedDnsApplications, application =>
            application.Source == "DnsInventory.CnameTarget");
        Assert.Contains(analysis.CnameTargetEvidence, item =>
            item.Contains("Conflicting CNAME targets for owner: example.com", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.CnameTargetEvidence, item => item.Contains("a.cloudflare.net", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.CnameTargetEvidence, item => item.Contains("z.azurefd.net", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CnameInventoryUsesTerminalEqualRankedServiceInsteadOfLexicalOrder()
    {
        var analysis = new DnsInventoryAnalysis
        {
            IncludeAuthorities = false,
            QueryOverride = (_, type, _) => Task.FromResult(new DnsResponse
            {
                Status = DnsResponseCode.NoError,
                Answers = type == DnsRecordType.CNAME
                    ? new[]
                    {
                        // Deliberately reverse DNS response order. Service selection
                        // must follow owner-to-target links, not array position.
                        new DnsAnswer { Name = "z.azurefd.net", Type = DnsRecordType.CNAME, DataRaw = "a.azureedge.net." },
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.CNAME, DataRaw = "z.azurefd.net." }
                    }
                    : Array.Empty<DnsAnswer>()
            })
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.Equal(DnsCnameTargetProvider.Azure, analysis.CnameTargetProvider);
        Assert.Equal(DnsCnameTargetService.AzureCdn, analysis.CnameTargetService);
        DetectedDnsApplication application = Assert.Single(
            analysis.DetectedDnsApplications,
            application => application.Id == "cname-target-azurecdn");
        Assert.Contains("a.azureedge.net", application.Evidence, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("z.azurefd.net", application.Evidence, StringComparison.OrdinalIgnoreCase);
        var evidence = analysis.CnameTargetEvidence.ToList();
        Assert.True(
            evidence.FindIndex(item => item.Contains("z.azurefd.net", StringComparison.OrdinalIgnoreCase)) <
            evidence.FindIndex(item => item.Contains("a.azureedge.net", StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public async Task CnameApplicationRetainsSelectedTerminalEvidenceAfterDiagnosticCap()
    {
        var analysis = new DnsInventoryAnalysis
        {
            IncludeAuthorities = false,
            QueryOverride = (_, type, _) => Task.FromResult(new DnsResponse
            {
                Status = DnsResponseCode.NoError,
                Answers = type == DnsRecordType.CNAME
                    ? new[]
                    {
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.CNAME, DataRaw = "a.cloudflare.net." },
                        new DnsAnswer { Name = "a.cloudflare.net", Type = DnsRecordType.CNAME, DataRaw = "b.cloudfront.net." },
                        new DnsAnswer { Name = "b.cloudfront.net", Type = DnsRecordType.CNAME, DataRaw = "c.github.io." },
                        new DnsAnswer { Name = "c.github.io", Type = DnsRecordType.CNAME, DataRaw = "d.netlify.app." },
                        new DnsAnswer { Name = "d.netlify.app", Type = DnsRecordType.CNAME, DataRaw = "z.azurefd.net." },
                        new DnsAnswer { Name = "z.azurefd.net", Type = DnsRecordType.CNAME, DataRaw = "terminal.azureedge.net." }
                    }
                    : Array.Empty<DnsAnswer>()
            })
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.Equal(DnsCnameTargetService.AzureCdn, analysis.CnameTargetService);
        DetectedDnsApplication application = Assert.Single(
            analysis.DetectedDnsApplications,
            item => item.Id == "cname-target-azurecdn");
        Assert.Contains("terminal.azureedge.net", application.Evidence, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            analysis.CnameTargetEvidence,
            item => item.Contains("terminal.azureedge.net", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CaaIssuerDetectorParsesCommonFormats()
    {
        var m = DnsCaaIssuerDetector.Detect(new[]
        {
            "0 issue \"letsencrypt.org; accounturi=https://example\"",
            "0 issue \";\""
        });

        Assert.True(m.Issuers.HasFlag(DnsCaaIssuers.LetsEncrypt));
        Assert.Contains(m.Evidence, e => e.Contains("letsencrypt.org", StringComparison.OrdinalIgnoreCase));
    }
}
