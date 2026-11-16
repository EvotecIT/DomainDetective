using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestCtTimelineProvider {
    private sealed class FakeProvider : ICtCertificateTransparencyProvider {
        private readonly Func<CtCertificateQuery, CtCertificateQueryResult> _answer;
        public FakeProvider(Func<CtCertificateQuery, CtCertificateQueryResult> answer) => _answer = answer;
        public string ProviderId => "ddct-api";
        public CtProviderProfile Profile { get; } = CtProviderProfiles.CreateDdctApi();
        public List<CtCertificateQuery> Queries { get; } = new();
        public Task<CtCertificateQueryResult> QueryAsync(CtCertificateQuery query, CtProviderRuntimeState? runtimeState = null, CancellationToken cancellationToken = default) {
            Queries.Add(query);
            return Task.FromResult(_answer(query));
        }
    }

    private static CtCertificateRecord Record(string sha, string issuer, DateTimeOffset logged) => new() {
        ProviderId = "ddct-api",
        Sha256Fingerprint = sha,
        Issuer = issuer,
        Subject = "CN=www.contoso.example",
        DnsNames = new[] { "www.contoso.example" },
        EntryTimestampUtc = logged,
        NotBeforeUtc = logged,
        NotAfterUtc = logged.AddDays(90)
    };

    [Fact]
    public async Task AConfiguredProviderSuppliesFirstSeenAndIssuersInsteadOfCrtSh() {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var provider = new FakeProvider(_ => new CtCertificateQueryResult {
            ProviderId = "ddct-api",
            Certificates = new[] {
                Record("aa", "CN=Example CA R1", now.AddDays(-400)),
                Record("bb", "CN=Example CA R1", now.AddDays(-30)),
                Record("cc", "CN=Other CA", now.AddDays(-3))
            }
        });
        int crtShCalls = 0;
        var analysis = new CertificateTransparencyTimelineAnalysis {
            Provider = provider,
            QueryOverride = (_, _) => { crtShCalls++; return Task.FromResult("[]"); }
        };

        await analysis.AnalyzeAsync("contoso.example", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Equal("ddct-api", analysis.Source);
        Assert.Equal(0, crtShCalls);
        Assert.Equal(CtCertificateQueryKind.DomainTreeCertificates, Assert.Single(provider.Queries).QueryKind);
        Assert.Equal(3, analysis.UniqueCertificateCount);
        Assert.Equal(now.AddDays(-400), analysis.FirstSeenUtc);
        Assert.Equal(2, analysis.IssuerCounts["CN=Example CA R1"]);
    }

    [Fact]
    public async Task AFailingProviderFallsBackToCrtShWithoutMixingAnswers() {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var provider = new FakeProvider(_ => throw new HttpRequestException("connection refused"));
        string json = "[{\"id\":1,\"issuer_name\":\"Issuer A\",\"entry_timestamp\":\"" + now.AddDays(-10).ToString("O") +
                      "\",\"common_name\":\"contoso.example\",\"name_value\":\"contoso.example\"}]";
        var analysis = new CertificateTransparencyTimelineAnalysis {
            Provider = provider,
            CrtShExactUrlTemplate = string.Empty,
            QueryOverride = (_, _) => Task.FromResult(json)
        };

        await analysis.AnalyzeAsync("contoso.example", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Equal("crt.sh", analysis.Source);
        Assert.Equal("connection refused", analysis.ProviderFailureReason);
        Assert.Equal(1, analysis.UniqueCertificateCount);
    }

    [Fact]
    public async Task AProviderAnswerCutOffAtThePageLimitIsMarkedCapped() {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        int page = 0;
        var provider = new FakeProvider(_ => {
            page++;
            return new CtCertificateQueryResult {
                ProviderId = "ddct-api",
                Certificates = new[] { Record("p" + page, "CN=Example CA", now.AddDays(-page)) },
                HasMore = true,
                ContinuationToken = "token-" + page
            };
        });
        var analysis = new CertificateTransparencyTimelineAnalysis { Provider = provider, ProviderMaxPages = 2 };

        await analysis.AnalyzeAsync("contoso.example", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Equal(2, provider.Queries.Count);
        // The earliest entries may be beyond the last page read, so first seen is not the domain's first certificate.
        Assert.True(analysis.ResultsCapped);
    }

    [Fact]
    public async Task AProviderAnswerThatEndsWithinThePageLimitIsComplete() {
        var provider = new FakeProvider(_ => new CtCertificateQueryResult {
            ProviderId = "ddct-api",
            Certificates = new[] { Record("only", "CN=Example CA", DateTimeOffset.UtcNow.AddDays(-5)) },
            HasMore = false
        });
        var analysis = new CertificateTransparencyTimelineAnalysis { Provider = provider, ProviderMaxPages = 2 };

        await analysis.AnalyzeAsync("contoso.example", new InternalLogger(), CancellationToken.None);

        Assert.False(analysis.ResultsCapped);
    }

    [Fact]
    public async Task AProviderThatSaysThereIsMoreButGivesNoTokenIsCapped() {
        var provider = new FakeProvider(_ => new CtCertificateQueryResult {
            ProviderId = "ddct-api",
            Certificates = new[] { Record("first", "CN=Example CA", DateTimeOffset.UtcNow.AddDays(-3)) },
            HasMore = true
        });
        var analysis = new CertificateTransparencyTimelineAnalysis { Provider = provider, ProviderMaxPages = 5 };

        await analysis.AnalyzeAsync("contoso.example", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.ResultsCapped);
    }
}
