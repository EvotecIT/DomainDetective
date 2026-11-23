using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Profiles;

namespace DomainDetective.Tests;

// Every evidence source maps its answers through one rule: complete only when everything asked answered and nothing
// was capped. A positive finding is reported but never turns partial coverage into complete coverage.
public class TestEvidenceCoverage {
    private static DNSBLRecord List(bool answered, bool listed) => new() { QuerySucceeded = answered, IsBlackListed = listed, BlackList = "list.example" };

    private static readonly Dictionary<string, (Func<EvidenceState> Map, EvidenceState Expected)> Cases = new() {
        ["feed: listed"] = (() => DomainRiskProfileBuilder.FeedState(ThreatIntelQueryState.Listed), EvidenceState.Observed),
        ["feed: clean"] = (() => DomainRiskProfileBuilder.FeedState(ThreatIntelQueryState.Clean), EvidenceState.Clean),
        ["feed: failed"] = (() => DomainRiskProfileBuilder.FeedState(ThreatIntelQueryState.Failed), EvidenceState.Failed),
        ["feed: not queried"] = (() => DomainRiskProfileBuilder.FeedState(ThreatIntelQueryState.NotQueried), EvidenceState.NotQueried),

        ["dnsbl: all answered, clean"] = (() => DomainRiskProfileBuilder.BlocklistState(new[] { List(true, false), List(true, false) }), EvidenceState.Clean),
        ["dnsbl: all answered, listed"] = (() => DomainRiskProfileBuilder.BlocklistState(new[] { List(true, true), List(true, false) }), EvidenceState.Observed),
        ["dnsbl: listed but another list failed"] = (() => DomainRiskProfileBuilder.BlocklistState(new[] { List(true, true), List(false, false) }), EvidenceState.Partial),
        ["dnsbl: clean but another list failed"] = (() => DomainRiskProfileBuilder.BlocklistState(new[] { List(true, false), List(false, false) }), EvidenceState.Partial),
        ["dnsbl: every list failed"] = (() => DomainRiskProfileBuilder.BlocklistState(new[] { List(false, false) }), EvidenceState.Failed),
        ["dnsbl: no lists"] = (() => DomainRiskProfileBuilder.BlocklistState(Array.Empty<DNSBLRecord>()), EvidenceState.NotQueried),

        ["ct: complete"] = (() => DomainRiskProfileBuilder.CtState(true, false), EvidenceState.Observed),
        ["ct: capped or a query failed"] = (() => DomainRiskProfileBuilder.CtState(true, true), EvidenceState.Partial),
        ["ct: failed"] = (() => DomainRiskProfileBuilder.CtState(false, false), EvidenceState.Failed),

        ["dns inventory: every type answered"] = (() => DomainRiskProfileBuilder.InventoryState(true, 6, 0), EvidenceState.Observed),
        ["dns inventory: some types failed"] = (() => DomainRiskProfileBuilder.InventoryState(true, 6, 2), EvidenceState.Partial),
        ["dns inventory: every type failed"] = (() => DomainRiskProfileBuilder.InventoryState(true, 6, 6), EvidenceState.Failed),
        ["dns inventory: query failed"] = (() => DomainRiskProfileBuilder.InventoryState(false, 6, 0), EvidenceState.Failed),

        ["dnssec: definite"] = (() => DomainRiskProfileBuilder.DnssecState(DnssecValidationStatus.Secure), EvidenceState.Observed),
        ["dnssec: indeterminate"] = (() => DomainRiskProfileBuilder.DnssecState(DnssecValidationStatus.Indeterminate), EvidenceState.Partial),
        ["dnssec: not checked"] = (() => DomainRiskProfileBuilder.DnssecState(DnssecValidationStatus.NotChecked), EvidenceState.Failed),

        ["registration date: parsed"] = (() => DomainRiskProfileBuilder.DateEvidence("2001-01-12", true, EvidenceState.Failed).Item1, EvidenceState.Observed),
        ["registration date: unreadable"] = (() => DomainRiskProfileBuilder.DateEvidence("someday", true, EvidenceState.Failed).Item1, EvidenceState.Partial),
        ["registration date: no answer"] = (() => DomainRiskProfileBuilder.DateEvidence(null, false, EvidenceState.Failed).Item1, EvidenceState.Failed),

        ["ip enrichment: complete"] = (() => DomainRiskProfileBuilder.NetworkState(true, false), EvidenceState.Observed),
        ["ip enrichment: address list capped"] = (() => DomainRiskProfileBuilder.NetworkState(true, true), EvidenceState.Partial),
        ["ip enrichment: failed"] = (() => DomainRiskProfileBuilder.NetworkState(false, false), EvidenceState.Failed),

        ["web scan: finished"] = (() => DomainRiskProfileBuilder.WebState(true), EvidenceState.Observed),
        ["web scan: did not finish"] = (() => DomainRiskProfileBuilder.WebState(false), EvidenceState.Partial),
    };

    public static IEnumerable<object[]> Names => Cases.Keys.Select(static name => new object[] { name });

    [Theory]
    [MemberData(nameof(Names))]
    public void EverySourceMapsItsStatesThroughTheSharedRule(string name) {
        (Func<EvidenceState> map, EvidenceState expected) = Cases[name];
        Assert.Equal(expected, map());
    }

    [Theory]
    [InlineData(0, 0, false, false, EvidenceState.NotQueried)]
    [InlineData(3, 0, false, false, EvidenceState.Failed)]
    [InlineData(3, 2, true, false, EvidenceState.Partial)]
    [InlineData(3, 3, true, true, EvidenceState.Partial)]
    [InlineData(3, 3, true, false, EvidenceState.Observed)]
    [InlineData(3, 3, false, false, EvidenceState.Clean)]
    public void AFindingNeverMakesPartialCoverageComplete(int asked, int answered, bool found, bool capped, EvidenceState expected) {
        Assert.Equal(expected, EvidenceCoverage.From(asked, answered, found, capped));
    }

    [Fact]
    public void ADomainListingOnPartlyAnsweredListsIsStillScoredAndStaysPartial() {
        var evidence = new DomainRiskEvidence {
            Domain = "contoso.example",
            DomainBlocklistState = DomainRiskProfileBuilder.BlocklistState(new[] { List(true, true), List(false, false) })
        };
        evidence.DomainBlocklists.Add("list.example");

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence);

        Assert.Contains(profile.Signals, s => s.Id == "reputation.domain-blocklist");
        Assert.Equal(EvidenceState.Partial, profile.Facets.Single(f => f.Kind == ProfileFacetKind.Reputation)
            .Evidence.Single(e => e.Id == "reputation.domain-blocklist").State);
    }

    [Fact]
    public void ACappedAddressListKeepsEveryNetworkItemPartial() {
        var evidence = new DomainRiskEvidence { Domain = "contoso.example", NetworkState = DomainRiskProfileBuilder.NetworkState(true, true) };
        evidence.Addresses.Add(new ProfileAddress {
            IpAddress = "192.0.2.1", Asn = 64500, Cidr = "192.0.2.0/24", CountrySource = IpCountrySource.GeoIp,
            HostingProvider = "Example Cloud", HostingMatchedBy = "192.0.2.0/24"
        });

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence);

        ProfileFacet network = profile.Facets.Single(f => f.Kind == ProfileFacetKind.Network);
        Assert.All(network.Evidence, item => Assert.Equal(EvidenceState.Partial, item.State));
        Assert.Contains("capped", network.Evidence.Single(e => e.Id == "network.asn").Note);
    }

    [Fact]
    public void ACappedCtHistoryIsPartialThroughout() {
        var evidence = new DomainRiskEvidence {
            Domain = "contoso.example", CtState = DomainRiskProfileBuilder.CtState(true, true), CtCapped = true, CtSource = "crt.sh",
            CtFirstSeenUtc = DateTimeOffset.UtcNow.AddDays(-3), UniqueCertificates = 4
        };

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence);

        Assert.All(profile.Facets.Single(f => f.Kind == ProfileFacetKind.Certificates).Evidence, item => Assert.Equal(EvidenceState.Partial, item.State));
        Assert.DoesNotContain(profile.Signals, s => s.Id == "certificates.first-seen.under30d");
    }
}
