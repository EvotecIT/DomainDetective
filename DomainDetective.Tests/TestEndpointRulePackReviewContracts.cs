using System;
using System.ComponentModel;
using System.Linq;
using System.Text.Json;
using DomainDetective.Providers.Endpoint;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestEndpointRulePackReviewContracts {
    [Theory]
    [InlineData("ip-cidr,label-prefix")]
    [InlineData("ipcidr")]
    [InlineData("i-p-cidr")]
    [InlineData("IpCidr")]
    [InlineData("IP-CIDR")]
    [InlineData(" hostname-regex ")]
    [InlineData("")]
    public void MatcherTokensRejectCompositeAndUndocumentedNames(string token) {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<EndpointMatcherType>(JsonSerializer.Serialize(token)));
        Assert.Throws<JsonException>(() => TypeDescriptor.GetConverter(typeof(EndpointMatcherType)).ConvertFromInvariantString(token));
    }

    [Fact]
    public void DocumentedMatcherTokensRoundTripThroughJsonAndConfiguration() {
        string[] tokens = { "label-prefix", "hostname-suffix", "hostname-regex", "ip-cidr", "cname-suffix", "cname-regex", "live-issuer", "ip-embedded-label", "azure-service-tag" };
        foreach (string token in tokens) {
            var parsed = JsonSerializer.Deserialize<EndpointMatcherType>(JsonSerializer.Serialize(token));
            Assert.Equal(JsonSerializer.Serialize(token), JsonSerializer.Serialize(parsed));
            Assert.Equal(parsed, TypeDescriptor.GetConverter(typeof(EndpointMatcherType)).ConvertFromInvariantString(token));
        }
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize(EndpointMatcherType.Undefined));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<EndpointMatcherType>("4"));
    }

    [Theory]
    [InlineData("DirectTls, SmtpStartTls")]
    [InlineData("SmtpStartTls, FtpExplicitTls")]
    [InlineData(" DirectTls")]
    [InlineData("DirectTls ")]
    [InlineData("directtls")]
    [InlineData("0")]
    public void TransportTokensRejectCompositeAndUndocumentedNames(string token) {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<CertificateProbeTransport>(JsonSerializer.Serialize(token)));
        Assert.Throws<JsonException>(() => TypeDescriptor.GetConverter(typeof(CertificateProbeTransport)).ConvertFromInvariantString(token));
    }

    [Fact]
    public void DeclaredTransportTokensRoundTrip() {
        foreach (CertificateProbeTransport mode in Enum.GetValues(typeof(CertificateProbeTransport))) {
            Assert.Equal(mode, JsonSerializer.Deserialize<CertificateProbeTransport>(JsonSerializer.Serialize(mode)));
            Assert.Equal(mode, TypeDescriptor.GetConverter(typeof(CertificateProbeTransport)).ConvertFromInvariantString(mode.ToString()));
        }
    }

    [Theory]
    [InlineData("azure-front-door", "edge.azurefd.net")]
    [InlineData("azure-cdn", "edge.azureedge.net")]
    [InlineData("azure-traffic-manager", "edge.trafficmanager.net")]
    [InlineData("redirection", "cdn.perf1.com")]
    public void LegacyHttpServiceScopeRemainsSeparateFromRawTlsClassification(string service, string target) {
        var input = new EndpointAttributionInput {
            HostName = "service.example.test", Port = 443, Service = "tls",
            CnameChain = new[] { target }, CertificateIssuer = "DigiCert Inc"
        };
        Assert.Null(new EndpointAttributionDetector().Detect(input).Primary);
        var identity = new CertificateObservationIdentity("tls-live", "AA",
            CertificateEndpointIdentity.Create(input.HostName, input.Port, input.Service), "synthetic", "https-443", "test");
        Assert.Contains(new EndpointRulePackEvaluator().Evaluate(input, identity, DateTimeOffset.UtcNow), hit => hit.ServiceId == service);
        input.Service = "HTTPS";
        Assert.Equal(service, new EndpointAttributionDetector().Detect(input).Primary?.ServiceId);
        input.Service = "HTTPS-Alt";
        Assert.Equal(service, new EndpointAttributionDetector().Detect(input).Primary?.ServiceId);
    }

    [Theory]
    [InlineData(EndpointMatcherType.HostnameRegex)]
    [InlineData(EndpointMatcherType.CnameRegex)]
    public void RegexTimeoutPreservesLaterOperandsAndRules(EndpointMatcherType type) {
        string slowName = new string('a', 55) + ".example.test";
        string host = type == EndpointMatcherType.HostnameRegex ? slowName : "service.example.test";
        var options = new EndpointRulePackOptions { UseBuiltInPacks = false };
        var pack = new EndpointRulePack { Id = "synthetic", Version = "1.0.0" };
        pack.Rules.Add(new EndpointPackRule { Id = "bounded-regex", Label = "Bounded regex", AnyOf = {
            new EndpointRuleMatcher { Type = type, Values = { "^(a+)+$", "\\.example\\.test$" } }
        } });
        pack.Rules.Add(new EndpointPackRule { Id = "other-rule", Label = "Other rule", AllOf = {
            new EndpointRuleMatcher { Type = EndpointMatcherType.HostnameSuffix, Values = { "example.test" } }
        } });
        options.Packs.Add(pack);
        var input = new EndpointAttributionInput { HostName = host, Port = 443, Service = "tls", CnameChain = new[] { slowName } };
        var identity = new CertificateObservationIdentity("tls-live", "AA", CertificateEndpointIdentity.Create(host, 443, "tls"), "synthetic", "https-443", "test");
        var hits = new EndpointRulePackEvaluator(options).Evaluate(input, identity, DateTimeOffset.UtcNow);
        Assert.Equal(2, hits.Count);
        Assert.Equal("\\.example\\.test$", Assert.Single(hits.Single(hit => hit.RuleId == "bounded-regex").Signals).Matched);
        Assert.Contains(hits, hit => hit.RuleId == "other-rule");
    }
}
