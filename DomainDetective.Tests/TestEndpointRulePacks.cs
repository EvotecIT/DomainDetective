using System;
using System.Linq;
using DomainDetective.Providers.Endpoint;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestEndpointRulePacks {
    private static readonly DateTimeOffset Observed = new(2026, 10, 21, 12, 0, 0, TimeSpan.Zero);

    private static CertificateObservationIdentity Identity(string host = "www.example.test", int port = 443, string observation = "42", string source = "tls-live", string fingerprint = "AA", string profile = "https-443", string vantage = "default")
        => new(source, fingerprint, CertificateEndpointIdentity.Create(host, port, "tls"), observation, profile, vantage);

    private static EndpointAttributionInput Input(string host = "www.example.test", int port = 443) => new() { HostName = host, Port = port, Service = "tls" };

    [Theory]
    [InlineData("localhost.example.test", "localhost", EndpointRuleEffect.ExcludeFromOwnerViews)]
    [InlineData("webmail.example.test", "hosting-stubs", EndpointRuleEffect.ExcludeFromOwnerViews)]
    [InlineData("enterpriseenrollment.example.test", "m365-pointers", EndpointRuleEffect.ExcludeFromOwnerViews)]
    [InlineData("address-192-0-2-44.isp.example.test", "isp-rdns", EndpointRuleEffect.ExcludeFromOwnerViews)]
    [InlineData("endpoint.pphosted.com", "cloud-saas", EndpointRuleEffect.TagOnly)]
    public void BuiltInDataClassifiesGenericTagsWithoutRemovingItsObservation(string host, string pack, EndpointRuleEffect effect) {
        var identity = Identity(host);
        var hits = new EndpointRulePackEvaluator().Evaluate(Input(host), identity, Observed);
        EndpointRuleHit hit = Assert.Single(hits, h => h.PackId == pack);
        Assert.Equal(effect, hit.Effect);
        Assert.Same(identity, hit.Identity);
        Assert.Equal("1.0.0", hit.PackVersion);
        Assert.Equal(Observed, hit.ObservedAtUtc);
        Assert.NotEmpty(hit.Signals);
        Assert.Contains(hit.Signals[0].Observed, hit.Reason);
    }

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.255.255.255", true)]
    [InlineData("::1", true)]
    [InlineData("128.0.0.1", false)]
    public void LoopbackPackUsesAddressBoundaries(string address, bool expected) {
        EndpointAttributionInput input = Input();
        input.IpAddresses = new[] { address };
        Assert.Equal(expected, new EndpointRulePackEvaluator().Evaluate(input, Identity(), Observed).Any(h => h.RuleId == "loopback-address"));
    }

    [Fact]
    public void ProviderTagNeedsThisEndpointsTargetAndLiveIssuerAndDefaultsToTagOnly() {
        var evaluator = new EndpointRulePackEvaluator();
        EndpointAttributionInput input = Input();
        input.CnameChain = new[] { "cdn.perf1.com" };
        Assert.DoesNotContain(evaluator.Evaluate(input, Identity(), Observed), h => h.PackId == "nameshield");
        input.CertificateIssuer = "DigiCert Inc";
        EndpointRuleHit hit = Assert.Single(evaluator.Evaluate(input, Identity(), Observed), h => h.PackId == "nameshield");
        Assert.Equal(EndpointRuleEffect.TagOnly, hit.Effect);
        Assert.False(hit.Expected);
        input.CertificateIssuer = "A different issuer";
        Assert.DoesNotContain(evaluator.Evaluate(input, Identity(), Observed), h => h.PackId == "nameshield");
        input.CertificateIssuer = "DigiCert Inc";
        input.CnameChain = new[] { "notperf1.com" };
        Assert.DoesNotContain(evaluator.Evaluate(input, Identity(), Observed), h => h.PackId == "nameshield");
        Assert.Throws<ArgumentException>(() => evaluator.Evaluate(input, Identity(port: 8443), Observed));
    }

    [Fact]
    public void DeploymentCanDisableOverrideAndExpectPacksWithoutMutatingBuiltIns() {
        var options = new EndpointRulePackOptions();
        options.Packs.Add(new EndpointRulePack { Id = "hosting-stubs", Enabled = false });
        options.Packs.Add(new EndpointRulePack { Id = "nameshield", Expected = true, Effect = EndpointRuleEffect.Quarantine });
        var evaluator = new EndpointRulePackEvaluator(options);
        Assert.DoesNotContain(evaluator.Evaluate(Input("webmail.example.test"), Identity("webmail.example.test"), Observed), h => h.PackId == "hosting-stubs");
        var input = Input();
        input.CnameChain = new[] { "cdn.perf1.com" };
        input.CertificateIssuer = "DigiCert";
        EndpointRuleHit hit = Assert.Single(evaluator.Evaluate(input, Identity(), Observed), h => h.PackId == "nameshield");
        Assert.True(hit.Expected);
        Assert.Equal(EndpointRuleEffect.Quarantine, hit.Effect);
        Assert.False(Assert.Single(EndpointRulePackCatalog.LoadBuiltIns(), p => p.Id == "nameshield").Expected);
    }

    [Fact]
    public void DeploymentExpectationDoesNotRequireALegacyAttributionProviderIdentifier() {
        var options = new EndpointRulePackOptions { UseBuiltInPacks = false };
        options.Packs.Add(new EndpointRulePack { Id = "deployment-service", Version = "1.0.0", Expected = true,
            Rules = { new EndpointPackRule { Id = "endpoint", Label = "Deployment service", AnyOf = { new EndpointRuleMatcher { Type = EndpointMatcherType.HostnameSuffix, Values = { "example.test" } } } } } });
        var hit = Assert.Single(new EndpointRulePackEvaluator(options).Evaluate(Input(), Identity(), Observed));
        Assert.True(hit.Expected);
        Assert.Equal(EndpointRuleEffect.TagOnly, hit.Effect);
        Assert.Empty(hit.ProviderId);
    }

    [Fact]
    public void CountsReconcileOverlappingRulesAndDoNotDeduplicateDifferentObservations() {
        var evaluator = new EndpointRulePackEvaluator();
        var input = Input("webmail.example.test");
        input.IpAddresses = new[] { "127.0.0.1" };
        var first = evaluator.Evaluate(input, Identity(input.HostName), Observed);
        var second = evaluator.Evaluate(input, Identity(input.HostName, observation: "43"), Observed);
        EndpointRuleHitSummary summary = evaluator.Summarize(first.Concat(first).Concat(second));
        Assert.Equal(2, summary.ExcludedObservations);
        Assert.Equal(1, summary.ExcludedEndpoints);
        Assert.Equal(2, summary.MatchedRuleCount);
        Assert.Equal(2, summary.OverlappingHits);
        Assert.Equal(2, Assert.Single(summary.Rules, r => r.PackId == "hosting-stubs").MatchedObservations);
        Assert.Contains(summary.Rules, r => r.PackId == "nameshield" && r.MatchedObservations == 0);
    }

    [Fact]
    public void CnameRegexUsesObservedTargetsAndPortableTokens() {
        var options = EndpointRulePackCatalog.Parse("""{"useBuiltInPacks":false,"packs":[{"id":"targets","version":"1.0.0","rules":[{"id":"pattern","label":"Target","anyOf":[{"type":"cname-regex","values":["^edge.*[.]provider[.]test$"]}]}]}]}""");
        var evaluator = new EndpointRulePackEvaluator(new EndpointRulePackOptions { UseBuiltInPacks = false, Packs = options.ToList() });
        var input = Input();
        input.CnameChain = new[] { "EDGE42.PROVIDER.TEST." };
        var hit = Assert.Single(evaluator.Evaluate(input, Identity(), Observed));
        Assert.Equal("EDGE42.PROVIDER.TEST.", Assert.Single(hit.Signals).Observed);
        input.CnameChain = new[] { "sub.edge42.provider.test" };
        Assert.Empty(evaluator.Evaluate(input, Identity(), Observed));
    }

    [Fact]
    public void IssuanceNamesNeverProveLiveProvidersOrIncreaseEndpointCounts() {
        var evaluator = new EndpointRulePackEvaluator();
        var input = Input("webmail.example.test");
        input.CertificateIssuer = "DigiCert Inc";
        input.CnameChain = new[] { "cdn.perf1.com" };
        input.IpAddresses = new[] { "127.0.0.1" };
        var identity = new CertificateObservationIdentity("ct", "AA", CertificateEndpointIdentity.Create(input.HostName, 443, "tls"), "ct-record", "issuance-name", "", isEndpointObservation: false);
        var hits = evaluator.Evaluate(input, identity, Observed);
        Assert.DoesNotContain(hits, hit => hit.PackId == "nameshield" || hit.RuleId == "loopback-address");
        var summary = evaluator.Summarize(hits);
        Assert.Equal(1, summary.ExcludedObservations);
        Assert.Equal(0, summary.ExcludedEndpoints);
        Assert.Equal(0, Assert.Single(summary.Rules, rule => rule.PackId == "hosting-stubs").MatchedEndpoints);
        Assert.NotEqual(identity, new CertificateObservationIdentity("ct", "AA", identity.Endpoint, "ct-record", "issuance-name", ""));
    }

    [Fact]
    public void IdentityPreservesEveryConsequentialDimensionAndFramesArbitrarySourceIds() {
        CertificateObservationIdentity original = Identity();
        Assert.Equal(original, Identity(fingerprint: "aa"));
        Assert.NotEqual(original, Identity(port: 8443));
        Assert.NotEqual(original, Identity(observation: "43"));
        Assert.NotEqual(original, Identity(source: "ct"));
        Assert.NotEqual(original, Identity(fingerprint: "BB"));
        Assert.NotEqual(original, Identity(profile: "another-profile"));
        Assert.NotEqual(original, Identity(vantage: "inside"));
        Assert.NotEqual(Identity(observation: "a|b", profile: "c"), Identity(observation: "a", profile: "b|c"));
        Assert.Throws<ArgumentException>(() => Identity(observation: ""));
    }

    [Theory]
    [InlineData("{\"packs\":[{\"id\":\"custom\",\"version\":\"1.0\"}]}")]
    [InlineData("{\"packs\":[{\"id\":\"custom\",\"version\":\"1.0.0\",\"rules\":[{\"id\":\"invalid\",\"label\":\"Invalid\",\"anyOf\":[{\"type\":\"ip-cidr\",\"values\":[\"999.0.0.0/24\"]}]}]}]}")]
    public void InvalidDeploymentDataFailsBeforeInventoryEvaluation(string json) {
        Assert.Throws<ArgumentException>(() => EndpointRulePackCatalog.Parse(json));
    }
}
