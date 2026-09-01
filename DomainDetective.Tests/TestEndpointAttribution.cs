using DomainDetective.Network;
using DomainDetective.Providers.Endpoint;
using DnsClientX;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestEndpointAttribution {
    [Fact]
    public async Task DnsEvidenceResolverRetainsFullCnameChainAndAddresses() {
        var responses = new Dictionary<(string, DnsRecordType), DnsAnswer[]> {
            [("www.example.com", DnsRecordType.CNAME)] = new[] { new DnsAnswer { Type = DnsRecordType.CNAME, DataRaw = "edge.example.net." } },
            [("edge.example.net", DnsRecordType.CNAME)] = new[] { new DnsAnswer { Type = DnsRecordType.CNAME, DataRaw = "tenant.azurefd.net." } },
            [("tenant.azurefd.net", DnsRecordType.CNAME)] = Array.Empty<DnsAnswer>(),
            [("tenant.azurefd.net", DnsRecordType.A)] = new[] { new DnsAnswer { Type = DnsRecordType.A, DataRaw = "203.0.113.10" } },
            [("tenant.azurefd.net", DnsRecordType.AAAA)] = new[] { new DnsAnswer { Type = DnsRecordType.AAAA, DataRaw = "2001:db8::10" } }
        };
        var resolver = new EndpointDnsEvidenceResolver {
            QueryDnsOverride = (name, type, _) => Task.FromResult(responses.TryGetValue((name, type), out DnsAnswer[]? value) ? value : Array.Empty<DnsAnswer>())
        };

        EndpointDnsEvidence evidence = await resolver.ResolveAsync("WWW.Example.COM.");

        Assert.Equal("tenant.azurefd.net", evidence.EffectiveHostName);
        Assert.Equal(new[] { "edge.example.net", "tenant.azurefd.net" }, evidence.CnameChain);
        Assert.Contains("203.0.113.10", evidence.Addresses);
        Assert.Contains("2001:db8::10", evidence.Addresses);
        Assert.False(evidence.LoopDetected);
        Assert.Empty(evidence.Errors);
        Assert.True(evidence.AddressResolutionComplete);
    }

    [Fact]
    public async Task DnsEvidenceResolverSelectsCnameOwnedByCurrentChainNode() {
        DnsAnswer[] shuffledChain = {
            new() { Name = "edge.example.net.", Type = DnsRecordType.CNAME, DataRaw = "tenant.azurefd.net." },
            new() { Name = "www.example.com.", Type = DnsRecordType.CNAME, DataRaw = "edge.example.net." }
        };
        var resolver = new EndpointDnsEvidenceResolver {
            QueryDnsOverride = (_, type, _) => Task.FromResult(
                type == DnsRecordType.CNAME ? shuffledChain : Array.Empty<DnsAnswer>())
        };

        EndpointDnsEvidence evidence = await resolver.ResolveAsync("www.example.com");

        Assert.Equal("tenant.azurefd.net", evidence.EffectiveHostName);
        Assert.Equal(new[] { "edge.example.net", "tenant.azurefd.net" }, evidence.CnameChain);
        Assert.False(evidence.LoopDetected);
    }

    [Fact]
    public async Task DnsEvidenceResolverReportsAmbiguousCnameWithoutChoosingByResponseOrder() {
        var resolver = new EndpointDnsEvidenceResolver {
            QueryDnsOverride = (_, type, _) => Task.FromResult(type == DnsRecordType.CNAME
                ? new[] {
                    new DnsAnswer { Name = "www.example.com", Type = type, DataRaw = "first.example.net" },
                    new DnsAnswer { Name = "www.example.com", Type = type, DataRaw = "second.example.net" }
                }
                : Array.Empty<DnsAnswer>())
        };

        EndpointDnsEvidence evidence = await resolver.ResolveAsync("www.example.com");

        Assert.Equal("www.example.com", evidence.EffectiveHostName);
        Assert.Empty(evidence.CnameChain);
        Assert.Contains(evidence.Errors, error => error.Contains("multiple distinct targets", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("203.0.113.20", "203.0.113.20")]
    [InlineData("2001:db8::20", "2001:db8::20")]
    [InlineData("[2001:db8::21]", "2001:db8::21")]
    [InlineData("::ffff:192.0.2.20", "192.0.2.20")]
    public async Task DnsEvidenceResolverTreatsLiteralAddressAsCompletedEvidence(
        string input,
        string expectedAddress) {
        int queryCount = 0;
        var resolver = new EndpointDnsEvidenceResolver {
            QueryDnsOverride = (_, _, _) => {
                queryCount++;
                return Task.FromResult(Array.Empty<DnsAnswer>());
            }
        };

        EndpointDnsEvidence evidence = await resolver.ResolveAsync(input);

        Assert.Equal(0, queryCount);
        Assert.True(evidence.AddressResolutionComplete);
        Assert.Equal(expectedAddress, Assert.Single(evidence.Addresses));
        Assert.Empty(evidence.CnameChain);
        Assert.Empty(evidence.Errors);
    }

    [Fact]
    public void EndpointParsersRemoveIpv6UriBracketsWithoutChangingUriFormatting() {
        CertificateServiceDescriptor https = CertificateServiceClassifier.Resolve(
            "https://[2001:db8::30]/",
            443);
        var mail = new MailTransportEndpoint("[2001:db8::31]", 25);
        var ftp = new FtpTlsEndpoint("[2001:db8::32]", 990, FtpTlsMode.Implicit);

        Assert.Equal("2001:db8::30", https.Host);
        Assert.Contains("[2001:db8::30]", https.Url);
        Assert.Equal("2001:db8::31", mail.HostName);
        Assert.Equal("2001:db8::32", ftp.HostName);
    }

    [Fact]
    public async Task DnsEvidenceResolverReportsCnameLoopWithoutDiscardingEvidence() {
        var resolver = new EndpointDnsEvidenceResolver {
            QueryDnsOverride = (name, type, _) => {
                if (type != DnsRecordType.CNAME) {
                    return Task.FromResult(Array.Empty<DnsAnswer>());
                }
                string next = name == "a.example.com" ? "b.example.com" : "a.example.com";
                return Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.CNAME, DataRaw = next } });
            }
        };

        EndpointDnsEvidence evidence = await resolver.ResolveAsync("a.example.com", CancellationToken.None);

        Assert.True(evidence.LoopDetected);
        Assert.Equal(new[] { "b.example.com" }, evidence.CnameChain);
        Assert.Contains(evidence.Errors, error => error.Contains("loop", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void EndpointIdentityIncludesServiceAndNormalizesHost() {
        CertificateEndpointIdentity https = CertificateEndpointIdentity.Create(" WWW.Example.COM. ", 443, "HTTPS");
        CertificateEndpointIdentity ldaps = CertificateEndpointIdentity.Create("www.example.com", 443, "LDAPS");

        Assert.Equal("www.example.com|443|HTTPS", https.Key);
        Assert.NotEqual(https, ldaps);
    }

    [Theory]
    [InlineData("100.64.0.1", IpAddressVisibility.Shared)]
    [InlineData("198.18.0.1", IpAddressVisibility.Reserved)]
    [InlineData("192.0.2.1", IpAddressVisibility.Documentation)]
    [InlineData("8.8.8.8", IpAddressVisibility.Public)]
    [InlineData("2001:db8::1", IpAddressVisibility.Documentation)]
    public void IpClassifierHandlesReusableRoutingScopes(string value, IpAddressVisibility expected) {
        Assert.True(IpAddressClassifier.TryClassify(value, out IpAddressVisibility actual));
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("192.0.2.1", "IPv4")]
    [InlineData("::ffff:192.0.2.1", "IPv4")]
    [InlineData("2001:db8::1", "IPv6")]
    public void IpClassifierReturnsStableAddressFamilyLabels(string value, string expected) {
        Assert.Equal(expected, IpAddressClassifier.GetAddressFamilyLabel(IPAddress.Parse(value)));
    }

    [Fact]
    public void CidrRangeMatchesIpv4AndIpv6AndRejectsWrongFamily() {
        IpCidrRange ipv4 = IpCidrRange.Parse("203.0.113.0/24");
        IpCidrRange ipv6 = IpCidrRange.Parse("2001:db8::/32");

        Assert.True(ipv4.Contains(IPAddress.Parse("203.0.113.42")));
        Assert.False(ipv4.Contains(IPAddress.Parse("203.0.114.1")));
        Assert.True(ipv6.Contains(IPAddress.Parse("2001:db8:1::1")));
        Assert.False(ipv6.Contains(IPAddress.Parse("203.0.113.42")));
    }

    [Fact]
    public void CidrRangeTranslatesIpv4MappedIpv6PrefixWithoutLosingBits() {
        IpCidrRange mapped = IpCidrRange.Parse("::ffff:192.0.2.0/120");
        IpCidrRange broadMapped = IpCidrRange.Parse("::ff00:0:0/80");

        Assert.Equal("192.0.2.0/24", mapped.ToString());
        Assert.True(mapped.Contains(IPAddress.Parse("192.0.2.42")));
        Assert.True(mapped.Contains(IPAddress.Parse("::ffff:192.0.2.42")));
        Assert.False(mapped.Contains(IPAddress.Parse("192.0.3.1")));
        Assert.Equal(80, broadMapped.PrefixLength);
        Assert.Equal(System.Net.Sockets.AddressFamily.InterNetworkV6, broadMapped.Network.AddressFamily);
        Assert.True(broadMapped.Contains(IPAddress.Parse("::ffff:192.0.2.42")));
    }

    [Fact]
    public void AzureCatalogParsesOfficialServiceTagShape() {
        const string json = "{\"changeNumber\":\"7\",\"cloud\":\"Public\",\"values\":[{\"name\":\"AzureFrontDoor.Frontend\",\"properties\":{\"changeNumber\":\"3\",\"region\":\"\",\"systemService\":\"AzureFrontDoor\",\"addressPrefixes\":[\"203.0.113.0/24\",\"2001:db8::/32\"]}}]}";

        AzureServiceTagCatalog catalog = AzureServiceTagCatalog.Parse(json, "test-catalog");

        Assert.Equal("7", catalog.ChangeNumber);
        Assert.Equal("Public", catalog.Cloud);
        Assert.Contains("AzureFrontDoor.Frontend", catalog.FindTags(IPAddress.Parse("203.0.113.8")));
        Assert.Contains("AzureFrontDoor.Frontend", catalog.FindTags(IPAddress.Parse("2001:db8::8")));
    }

    [Theory]
    [InlineData("edge.azurefd.net", "azure-front-door")]
    [InlineData("edge.azureedge.net", "azure-cdn")]
    [InlineData("edge.trafficmanager.net", "azure-traffic-manager")]
    [InlineData("cdn.perf1.com", "redirection")]
    public void CnameSignalsProduceDistinctPrimaryServices(string cname, string expectedService) {
        var detector = new EndpointAttributionDetector();

        EndpointAttributionResult result = detector.Detect(new EndpointAttributionInput {
            HostName = "service.example.com",
            Port = 443,
            Service = "HTTPS",
            CnameChain = new[] { cname }
        });

        Assert.NotNull(result.Primary);
        Assert.Equal(expectedService, result.Primary!.ServiceId);
        Assert.Contains(result.Primary.Evidence, evidence => evidence.Kind == EndpointAttributionSignalKind.Cname);
    }

    [Fact]
    public void IssuerOnlyIsReviewCandidateNotPrimaryAttribution() {
        var detector = new EndpointAttributionDetector();

        EndpointAttributionResult result = detector.Detect(new EndpointAttributionInput {
            HostName = "unrelated.example.com",
            Port = 443,
            Service = "HTTPS",
            CertificateIssuer = "CN=DigiCert Global G2"
        });

        Assert.Null(result.Primary);
        Assert.NotEmpty(result.Candidates);
        Assert.All(result.Candidates, candidate => Assert.False(candidate.EligibleAsPrimary));
    }

    [Fact]
    public void CurrentAzureServiceTagCanEstablishFrontDoorAttribution() {
        const string json = "{\"changeNumber\":\"12\",\"cloud\":\"Public\",\"values\":[{\"name\":\"AzureFrontDoor.Frontend\",\"properties\":{\"addressPrefixes\":[\"203.0.113.0/24\"]}}]}";
        AzureServiceTagCatalog tags = AzureServiceTagCatalog.Parse(json, "downloaded-service-tags.json");
        var detector = new EndpointAttributionDetector();

        EndpointAttributionResult result = detector.Detect(new EndpointAttributionInput {
            HostName = "service.example.com",
            Port = 443,
            Service = "HTTPS",
            IpAddresses = new[] { "203.0.113.20" },
            AzureServiceTags = tags
        });

        Assert.Equal("azure-front-door", result.Primary?.ServiceId);
        Assert.Contains(result.Primary!.Evidence, evidence =>
            evidence.Kind == EndpointAttributionSignalKind.AzureServiceTag &&
            evidence.Source == "downloaded-service-tags.json");
        Assert.Equal("downloaded-service-tags.json", result.AzureServiceTagSource);
        Assert.Equal("12", result.AzureServiceTagChangeNumber);
        Assert.Equal("Public", result.AzureServiceTagCloud);
        Assert.NotNull(result.AzureServiceTagRetrievedAtUtc);
    }

    [Fact]
    public void PointInTimeIpSeedWithGenericIssuerRemainsReviewOnly() {
        var detector = new EndpointAttributionDetector();

        EndpointAttributionResult result = detector.Detect(new EndpointAttributionInput {
            HostName = "service.example.com",
            Port = 443,
            Service = "HTTPS",
            IpAddresses = new[] { "81.92.94.54" },
            CertificateIssuer = "CN=DigiCert TLS RSA SHA256 2020 CA1"
        });

        Assert.Null(result.Primary);
        EndpointAttributionCandidate candidate = Assert.Single(result.Candidates, item => item.RuleId == "builtin.nameshield.redirection");
        Assert.False(candidate.EligibleAsPrimary);
        Assert.Contains(candidate.Evidence, evidence => evidence.Kind == EndpointAttributionSignalKind.IpAddress);
        Assert.Contains(candidate.Evidence, evidence => evidence.Kind == EndpointAttributionSignalKind.CertificateIssuer);
    }

    [Fact]
    public void PointInTimeIpSeedAloneRemainsReviewCandidate() {
        EndpointAttributionResult result = new EndpointAttributionDetector().Detect(new EndpointAttributionInput {
            HostName = "service.example.com",
            Port = 443,
            Service = "HTTPS",
            IpAddresses = new[] { "81.92.94.54" }
        });

        Assert.Null(result.Primary);
        EndpointAttributionCandidate candidate = Assert.Single(result.Candidates, item => item.RuleId == "builtin.nameshield.redirection");
        Assert.False(candidate.EligibleAsPrimary);
    }

    [Theory]
    [InlineData("FTPS-EXPLICIT")]
    [InlineData("SMTP-STARTTLS")]
    public void HttpManagedServiceRulesDoNotClassifyOtherProtocols(string service) {
        EndpointAttributionResult result = new EndpointAttributionDetector().Detect(new EndpointAttributionInput {
            HostName = "service.example.com",
            Port = service == "FTPS-EXPLICIT" ? 21 : 25,
            Service = service,
            CnameChain = new[] { "tenant.azurefd.net", "cdn.perf1.com" },
            IpAddresses = new[] { "81.92.94.54" },
            CertificateIssuer = "DigiCert"
        });

        Assert.DoesNotContain(result.Candidates, candidate =>
            candidate.RuleId == "builtin.microsoft.azure-front-door" ||
            candidate.RuleId == "builtin.nameshield.redirection");
    }

    [Fact]
    public void CustomRuleReplacesBuiltInRuleByStableIdentifier() {
        EndpointAttributionCatalog catalog = EndpointAttributionCatalog.CreateDefault();
        var custom = new EndpointAttributionRule {
            RuleId = "custom.edge",
            RuleVersion = "1",
            ProviderId = "example",
            ServiceId = "edge",
            DisplayName = "Example Edge"
        };
        custom.CnameSuffixes.Add("edge.example.net");
        catalog.AddOrReplace(custom);

        EndpointAttributionResult result = new EndpointAttributionDetector(catalog).Detect(new EndpointAttributionInput {
            HostName = "www.example.com",
            CnameChain = new[] { "tenant.edge.example.net" }
        });

        Assert.Equal("example", result.Primary?.ProviderId);
        Assert.Equal("custom.edge", result.Primary?.RuleId);
        Assert.Single(result.Candidates, candidate => candidate.RuleId == "custom.edge");
    }

    [Fact]
    public void EqualEligibleCandidatesRemainExplicitlyAmbiguous() {
        var catalog = new EndpointAttributionCatalog();
        foreach (string provider in new[] { "provider-a", "provider-b" }) {
            var rule = new EndpointAttributionRule {
                RuleId = provider + ".edge",
                RuleVersion = "1",
                ProviderId = provider,
                ServiceId = "edge",
                DisplayName = provider
            };
            rule.CnameSuffixes.Add("shared.edge.example");
            catalog.Rules.Add(rule);
        }

        EndpointAttributionResult result = new EndpointAttributionDetector(catalog).Detect(new EndpointAttributionInput {
            HostName = "www.example.com",
            Port = 443,
            Service = "HTTPS",
            CnameChain = new[] { "tenant.shared.edge.example" }
        });

        Assert.True(result.IsAmbiguous);
        Assert.Null(result.Primary);
        Assert.Equal(2, result.Candidates.Count(candidate => candidate.EligibleAsPrimary));
    }

    [Fact]
    public void EqualRulesThatAgreeOnIdentityAreNotAmbiguous() {
        var catalog = new EndpointAttributionCatalog();
        foreach (string ruleId in new[] { "shared.edge.a", "shared.edge.b" }) {
            var rule = new EndpointAttributionRule {
                RuleId = ruleId,
                RuleVersion = "1",
                ProviderId = "shared-provider",
                ServiceId = "edge",
                DisplayName = "Shared Edge"
            };
            rule.CnameSuffixes.Add("shared.edge.example");
            catalog.Rules.Add(rule);
        }

        EndpointAttributionResult result = new EndpointAttributionDetector(catalog).Detect(new EndpointAttributionInput {
            HostName = "www.example.com",
            Port = 443,
            Service = "HTTPS",
            CnameChain = new[] { "tenant.shared.edge.example" }
        });

        Assert.False(result.IsAmbiguous);
        Assert.Equal("shared-provider", result.Primary?.ProviderId);
        Assert.Equal(2, result.Candidates.Count(candidate => candidate.EligibleAsPrimary));
    }
}
