using System;
using DomainDetective.Providers.Endpoint;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestEndpointRulePackAttribution {
    [Theory]
    [InlineData("150.171.109.1")]
    [InlineData("150.171.110.1")]
    public void ClassificationAddressSeedDoesNotEstablishLegacyAttribution(string address) {
        var input = new EndpointAttributionInput {
            HostName = "service.example.test", Port = 443, Service = "HTTPS",
            IpAddresses = new[] { address }
        };

        EndpointAttributionResult result = new EndpointAttributionDetector().Detect(input);

        Assert.Null(result.Primary);
        Assert.Empty(result.Candidates);

        input.CertificateIssuer = "DigiCert Inc";
        var identity = new CertificateObservationIdentity("tls-live", "AA",
            CertificateEndpointIdentity.Create(input.HostName, input.Port, input.Service),
            "synthetic-observation", "https-443", "test");
        var hits = new EndpointRulePackEvaluator().Evaluate(input, identity,
            new DateTimeOffset(2026, 10, 27, 0, 0, 0, TimeSpan.Zero));
        EndpointRuleHit hit = Assert.Single(hits, value => value.ServiceId == "azure-front-door");
        Assert.Contains(hit.Signals, signal => signal.Type == EndpointMatcherType.IpCidr);
    }

    [Theory]
    [InlineData("150.171.109.1")]
    [InlineData("150.171.110.1")]
    public void CurrentServiceTagKeepsItsLegacyScoreWithoutCountingTheSeedAgain(string address) {
        const string json = "{\"values\":[{\"name\":\"AzureFrontDoor.Frontend\",\"properties\":{\"addressPrefixes\":[\"150.171.109.0/24\",\"150.171.110.0/24\"]}}]}";
        var input = new EndpointAttributionInput {
            HostName = "service.example.test", Port = 443, Service = "HTTPS",
            IpAddresses = new[] { address },
            AzureServiceTags = AzureServiceTagCatalog.Parse(json, "synthetic-service-tags.json")
        };

        EndpointAttributionResult result = new EndpointAttributionDetector().Detect(input);

        Assert.NotNull(result.Primary);
        Assert.Equal("azure-front-door", result.Primary.ServiceId);
        Assert.Equal(.75, result.Primary.Score);
        EndpointAttributionEvidence evidence = Assert.Single(result.Primary.Evidence);
        Assert.Equal(EndpointAttributionSignalKind.AzureServiceTag, evidence.Kind);
        Assert.Equal("synthetic-service-tags.json", evidence.Source);
    }
}
