using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Profiles;
using DomainDetective.Reports;

namespace DomainDetective.Tests;

public class TestDomainRiskProfile {
    private static readonly DateTimeOffset Now = new(2026, 11, 16, 9, 0, 0, TimeSpan.Zero);

    // Every core source answered and found nothing; the domain is old and unremarkable.
    private static DomainRiskEvidence Answered() {
        var evidence = new DomainRiskEvidence {
            Domain = "contoso.example",
            DomainBlocklistState = EvidenceState.Clean,
            HostBlocklistState = EvidenceState.Clean,
            HostsChecked = 3,
            RegistrationSource = "RDAP",
            CreatedState = EvidenceState.Observed,
            CreatedUtc = Now.AddYears(-2),
            ExpiryState = EvidenceState.Observed,
            ExpiresUtc = Now.AddYears(1),
            StatusState = EvidenceState.Observed,
            Statuses = new List<string> { "clientTransferProhibited" },
            RegistrarState = EvidenceState.Observed,
            Registrar = "Example Registrar",
            CtState = EvidenceState.Observed,
            CtSource = "crt.sh",
            CtFirstSeenUtc = Now.AddYears(-2),
            UniqueCertificates = 12,
            InventoryState = EvidenceState.Observed,
            NameServerState = EvidenceState.Observed,
            DnssecState = EvidenceState.Observed,
            Dnssec = DnssecValidationStatus.Insecure,
            PtrState = EvidenceState.Observed,
            NetworkState = EvidenceState.Observed
        };
        evidence.Feeds.AddRange(Feeds(EvidenceState.Clean));
        evidence.Addresses.Add(new ProfileAddress {
            IpAddress = "192.0.2.10", Asn = 64500, AsName = "EXAMPLE-NET", Country = "NL",
            CountrySource = IpCountrySource.RdapRegistration, HostingProvider = "Example Cloud", HostingMatchedBy = "192.0.2.0/24"
        });
        return evidence;
    }

    private static IEnumerable<ThreatFeedEvidence> Feeds(EvidenceState state) => new[] {
        new ThreatFeedEvidence { Id = "gsb", Name = "Google Safe Browsing", Weight = 0.25, State = state, Action = "Add a Google Safe Browsing API key" },
        new ThreatFeedEvidence { Id = "virustotal", Name = "VirusTotal", Weight = 0.20, State = state, Action = "Add a VirusTotal API key" },
        new ThreatFeedEvidence { Id = "phishtank", Name = "PhishTank", Weight = 0.10, State = state },
        new ThreatFeedEvidence { Id = "urlhaus", Name = "URLhaus", Weight = 0.10, State = state },
        new ThreatFeedEvidence { Id = "openphish", Name = "OpenPhish", Weight = 0.10, State = state }
    };

    private static void List(DomainRiskEvidence evidence, string feedId) {
        ThreatFeedEvidence feed = evidence.Feeds.Single(f => f.Id == feedId);
        feed.State = EvidenceState.Observed;
        feed.Listed = true;
    }

    [Fact]
    public void MissingEvidenceLowersConfidenceAndLeavesTheScoreAlone() {
        DomainRiskEvidence answered = Answered();
        answered.CreatedUtc = Now.AddDays(-45);
        DomainRiskEvidence unanswered = Answered();
        unanswered.CreatedUtc = Now.AddDays(-45);
        unanswered.Feeds.Clear();
        unanswered.Feeds.AddRange(Feeds(EvidenceState.NotQueried));
        unanswered.CtState = EvidenceState.Failed;
        unanswered.DnssecState = EvidenceState.Failed;

        DomainRiskProfile full = DomainRiskProfileEvaluator.Evaluate(answered, Now);
        DomainRiskProfile partial = DomainRiskProfileEvaluator.Evaluate(unanswered, Now);

        Assert.Equal(12, full.RiskScore);
        Assert.Equal(full.RiskScore, partial.RiskScore);
        Assert.Equal(full.RiskLevel, partial.RiskLevel);
        Assert.True(partial.ConfidenceScore < full.ConfidenceScore);
        Assert.Contains(partial.Gaps, g => g.EvidenceId == "reputation.gsb" && g.Action.StartsWith("Add a Google Safe Browsing API key", StringComparison.Ordinal));
    }

    [Fact]
    public void ACleanAnswerCountsAsEvidenceButAddsNoRisk() {
        DomainRiskEvidence clean = Answered();
        DomainRiskEvidence notQueried = Answered();
        notQueried.DomainBlocklistState = EvidenceState.NotQueried;

        DomainRiskProfile withAnswer = DomainRiskProfileEvaluator.Evaluate(clean, Now);
        DomainRiskProfile withoutAnswer = DomainRiskProfileEvaluator.Evaluate(notQueried, Now);

        Assert.Equal(withAnswer.RiskScore, withoutAnswer.RiskScore);
        Assert.True(withAnswer.EvidenceScore > withoutAnswer.EvidenceScore);
    }

    [Fact]
    public void AFeedListingHoldsTheLevelAtHighAndCapsConfidenceWhenItIsTheOnlySource() {
        DomainRiskEvidence evidence = Answered();
        List(evidence, "gsb");

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence, Now);

        Assert.Equal(DomainRiskLevel.High, profile.RiskLevel);
        Assert.True(profile.RiskScore >= 55);
        Assert.Equal("Google Safe Browsing", profile.RestsOn);
        Assert.True(profile.ConfidenceScore <= 0.74);
        Assert.Equal(EvidenceConfidence.Medium, profile.Confidence);
    }

    [Fact]
    public void TrustSignalsNeverPullADecisiveListingBelowHigh() {
        DomainRiskEvidence evidence = Answered();
        evidence.CreatedUtc = Now.AddYears(-12);
        evidence.Dnssec = DnssecValidationStatus.Secure;
        List(evidence, "gsb");

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence, Now);

        Assert.Contains(profile.Signals, s => s.Points < 0);
        Assert.Equal(DomainRiskLevel.High, profile.RiskLevel);
    }

    [Fact]
    public void TheWorkedExampleScoresHighAndNamesTheSourceItRestsOn() {
        DomainRiskEvidence evidence = Answered();
        List(evidence, "gsb");
        evidence.RegistrationSource = "WHOIS";
        evidence.CreatedUtc = Now.AddDays(-12);
        evidence.StatusState = EvidenceState.Failed;
        evidence.CtSource = "crt.sh";
        evidence.CtFirstSeenUtc = Now.AddDays(-11);

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence, Now);

        // Listing 40 + registered 12 days ago 20 + first certificate 11 days ago 8.
        Assert.Equal(68, profile.RiskScore);
        Assert.Equal(DomainRiskLevel.High, profile.RiskLevel);
        Assert.Equal("Google Safe Browsing", profile.RestsOn);
        Assert.Contains(profile.Signals, s => s.Id == "certificates.first-seen.under30d");
        Assert.Contains(profile.Gaps, g => g.EvidenceId == "registration.status");
    }

    [Fact]
    public void ADdctFirstSeenIsNotScoredBecauseDdctMayNotHoldTheWholeHistory() {
        DomainRiskEvidence evidence = Answered();
        evidence.CtSource = "ddct-api";
        evidence.CtFirstSeenUtc = Now.AddDays(-11);

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence, Now);

        Assert.DoesNotContain(profile.Signals, s => s.Id == "certificates.first-seen.under30d");
        EvidenceItem firstSeen = profile.Facets.Single(f => f.Kind == ProfileFacetKind.Certificates).Evidence.Single(e => e.Id == "certificates.first-seen");
        Assert.Equal(EvidenceState.Partial, firstSeen.State);
        Assert.Contains("may be older", firstSeen.Note);
    }

    [Fact]
    public void AConfirmedReverseDnsMismatchIsReportedWhenAnotherLookupDidNotAnswer() {
        DomainRiskEvidence evidence = Answered();
        // One address resolves elsewhere (a confirmed mismatch); another's forward lookup returned nothing.
        evidence.PtrState = EvidenceCoverage.From(2, 1, found: true);
        evidence.MailHostsWithoutFcrDns = 1;

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence, Now);

        Assert.Contains(profile.Signals, s => s.Id == "dns.mail-ptr");
        Assert.Equal(EvidenceState.Partial, profile.Facets.Single(f => f.Kind == ProfileFacetKind.Dns).Evidence.Single(e => e.Id == "dns.ptr").State);
    }

    [Fact]
    public void AFutureCreationDateIsNotAYoungDomain() {
        DomainRiskEvidence evidence = Answered();
        evidence.CreatedUtc = Now.AddDays(5);

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence, Now);

        Assert.DoesNotContain(profile.Signals, s => s.Id.StartsWith("registration.age", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("05/11/2026", EvidenceState.Partial)]
    [InlineData("25/11/2026", EvidenceState.Observed)]
    [InlineData("2026-05-11", EvidenceState.Observed)]
    [InlineData("\u0660\u0665/\u0661\u0661/2026", EvidenceState.Partial)]
    public void ADayMonthOrderThatCannotBeToldApartDoesNotDateTheDomain(string text, EvidenceState expected) {
        Assert.Equal(expected, DomainRiskProfileBuilder.DateEvidence(text, true, EvidenceState.Failed).Item1);
    }

    [Fact]
    public void NoResolvedAddressesIsNotACleanNetwork() {
        DomainRiskEvidence evidence = Answered();
        evidence.Addresses.Clear();

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence, Now);

        Assert.All(profile.Facets.Single(f => f.Kind == ProfileFacetKind.Network).Evidence, item => Assert.Equal(EvidenceState.NotAvailable, item.State));
    }

    [Fact]
    public void OneVirusTotalEngineAddsWeightButDoesNotDecideTheLevel() {
        DomainRiskEvidence evidence = Answered();
        List(evidence, "virustotal");

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence, Now);

        RiskSignal signal = Assert.Single(profile.Signals, s => s.Id == "reputation.listed.virustotal");
        Assert.False(signal.Decisive);
        Assert.Equal(10, signal.Points);
        Assert.DoesNotContain("Listed by", signal.Reason);
    }

    [Fact]
    public void IndependentSourcesCorroborateTheLevel() {
        DomainRiskEvidence evidence = Answered();
        List(evidence, "gsb");
        List(evidence, "phishtank");
        evidence.DomainBlocklists.Add("dbl.example");
        evidence.DomainBlocklistState = EvidenceState.Observed;

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence, Now);

        // Without any one of the three sources, the other two still hold the level at High.
        Assert.Equal(DomainRiskLevel.High, profile.RiskLevel);
        Assert.Null(profile.RestsOn);
        Assert.True(profile.Corroborated);
        Assert.True(profile.ConfidenceScore > profile.EvidenceScore);
    }

    [Fact]
    public void OneFacetCannotCarryMoreThanItsCap() {
        DomainRiskEvidence evidence = Answered();
        evidence.CreatedUtc = Now.AddDays(-3);
        evidence.Statuses.Add("serverHold");
        evidence.ExpiresUtc = Now.AddDays(-1);

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence, Now);

        Assert.Equal(55, profile.Signals.Where(s => s.Facet == ProfileFacetKind.Registration).Sum(s => s.Points));
        Assert.Equal(30, profile.RiskScore);
    }

    [Fact]
    public void TooLittleEvidenceIsNotRatedAndNeverReadsAsSafe() {
        var evidence = new DomainRiskEvidence { Domain = "fabrikam.example", InventoryState = EvidenceState.Observed };
        evidence.Feeds.AddRange(Feeds(EvidenceState.NotQueried));

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence, Now);

        Assert.False(profile.Rated);
        Assert.Equal("Not rated", AssessmentReportWording.RiskValue(profile));
        Assert.StartsWith("Not rated", AssessmentReportWording.RiskVerdict(profile));
    }

    [Fact]
    public void ANoSignalVerdictNamesTheEvidenceLimitUnlessConfidenceIsHigh() {
        DomainRiskEvidence partial = Answered();
        partial.Feeds.Clear();
        partial.Feeds.AddRange(Feeds(EvidenceState.NotQueried));
        partial.CreatedUtc = Now.AddYears(-1).AddDays(-30);

        DomainRiskProfile low = DomainRiskProfileEvaluator.Evaluate(partial, Now);

        Assert.Equal(DomainRiskLevel.None, low.RiskLevel);
        Assert.NotEqual(EvidenceConfidence.High, low.Confidence);
        Assert.StartsWith("No risk signals found in the evidence collected, with medium confidence", AssessmentReportWording.RiskVerdict(low));
    }

    [Fact]
    public void RegistrationCountryIsPartialEvidenceNotServerLocation() {
        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(Answered(), Now);

        EvidenceItem country = profile.Facets.Single(f => f.Kind == ProfileFacetKind.Network).Evidence.Single(e => e.Id == "network.country");
        Assert.Equal(EvidenceState.Partial, country.State);
        Assert.Contains("registration country", country.Note);
    }

    [Fact]
    public void OptionalFacetsCountOnlyWhenTheirSourceRan() {
        DomainRiskProfile withoutWeb = DomainRiskProfileEvaluator.Evaluate(Answered(), Now);
        DomainRiskEvidence scanned = Answered();
        scanned.WebState = EvidenceState.Observed;
        scanned.Technologies.Add("Nginx");
        DomainRiskProfile withWeb = DomainRiskProfileEvaluator.Evaluate(scanned, Now);

        Assert.False(withoutWeb.Facets.Single(f => f.Kind == ProfileFacetKind.Web).Counted);
        Assert.True(withWeb.Facets.Single(f => f.Kind == ProfileFacetKind.Web).Counted);
        Assert.False(withWeb.Facets.Single(f => f.Kind == ProfileFacetKind.History).Counted);
        Assert.DoesNotContain(withoutWeb.Gaps, g => g.EvidenceId.StartsWith("web.", StringComparison.Ordinal) || g.EvidenceId.StartsWith("history.", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("2001-01-12T05:00:00Z", 2001, 1, 12)]
    [InlineData("12-Jan-2001", 2001, 1, 12)]
    [InlineData("2001.01.12 05:00:00", 2001, 1, 12)]
    [InlineData("12.01.2001", 2001, 1, 12)]
    [InlineData("2001-01-12 (registered)", 2001, 1, 12)]
    public void ParsesRegistrationDatesAsRegistriesWriteThem(string text, int year, int month, int day) {
        Assert.True(DomainRiskProfileBuilder.TryParseDate(text, out DateTimeOffset value));
        Assert.Equal(new DateTime(year, month, day), value.UtcDateTime.Date);
    }

    [Fact]
    public async System.Threading.Tasks.Task ThreatIntelTellsANeverQueriedFeedFromACleanOne() {
        var analysis = new ThreatIntelAnalysis {
            EnableUrlHaus = false,
            GoogleSafeBrowsingOverride = _ => System.Threading.Tasks.Task.FromResult("{}")
        };

        await analysis.Analyze("contoso.example", "key", null, null, new InternalLogger());

        Assert.Equal(ThreatIntelQueryState.Clean, analysis.Listings.Single(l => l.Source == ThreatIntelSource.GoogleSafeBrowsing).State);
        Assert.Equal(ThreatIntelQueryState.NotQueried, analysis.Listings.Single(l => l.Source == ThreatIntelSource.VirusTotal).State);
        Assert.Equal(ThreatIntelQueryState.NotQueried, analysis.Listings.Single(l => l.Source == ThreatIntelSource.UrlHaus).State);
    }

    [Fact]
    public void EvidenceSeenReportsCoverageNotTheCappedConfidence() {
        DomainRiskEvidence evidence = Answered();
        List(evidence, "gsb");

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence, Now);

        // The level rests on one feed, so confidence is capped; the evidence itself was almost all seen.
        Assert.True(profile.ConfidenceScore <= 0.74);
        Assert.True(profile.EvidenceScore > 0.9);
        string expected = ((int)Math.Round(profile.EvidenceScore * 100, MidpointRounding.AwayFromZero)).ToString(System.Globalization.CultureInfo.InvariantCulture) + "% of evidence seen";
        Assert.Equal(expected, AssessmentReportWording.ConfidencePercent(profile));
        Assert.StartsWith(expected.Replace(" of evidence seen", " seen"), AssessmentReportWording.ConfidenceValue(profile));
    }

    [Fact]
    public void AWebScanThatIsNotForThisDomainIsIgnored() {
        var health = new DomainHealthCheck();
        // A scan left over from another run carries technologies but no domain this profile can claim.
        health.WebStaticScanAnalysis.TechDetections.Add("Nginx");

        DomainRiskEvidence evidence = DomainRiskProfileBuilder.CollectEvidence(health);

        Assert.Equal(EvidenceState.NotQueried, evidence.WebState);
        Assert.Empty(evidence.Technologies);
    }

    [Fact]
    public void OneEnrichedAddressDoesNotMakeTheNetworkComplete() {
        DomainRiskEvidence evidence = Answered();
        // A second address whose RDAP lookup failed: no network data and no provider.
        evidence.Addresses.Add(new ProfileAddress { IpAddress = "192.0.2.20" });

        DomainRiskProfile profile = DomainRiskProfileEvaluator.Evaluate(evidence, Now);

        ProfileFacet network = profile.Facets.Single(f => f.Kind == ProfileFacetKind.Network);
        Assert.Equal(EvidenceState.Partial, network.Evidence.Single(e => e.Id == "network.asn").State);
        Assert.Equal(EvidenceState.Partial, network.Evidence.Single(e => e.Id == "network.hosting").State);
        Assert.Contains("1 of 2 addresses", network.Evidence.Single(e => e.Id == "network.asn").Note);
        Assert.Contains(profile.Gaps, g => g.EvidenceId == "network.asn");
    }

    [Theory]
    [InlineData(DnsClientX.DnsResponseCode.NXDomain, 1, EvidenceState.Observed)]
    [InlineData(DnsClientX.DnsResponseCode.ServerFailure, 0, EvidenceState.Failed)]
    public async System.Threading.Tasks.Task OnlyAConclusiveAnswerConfirmsAMissingPtr(DnsClientX.DnsResponseCode ptrStatus, int withoutFcrDns, EvidenceState ptrState) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
            name = name.TrimEnd('.');
            var answers = Array.Empty<DnsClientX.DnsAnswer>();
            var status = DnsClientX.DnsResponseCode.NoError;
            if (name == "example.test" && type == DnsClientX.DnsRecordType.MX) {
                answers = new[] { new DnsClientX.DnsAnswer { Name = name, Type = type, DataRaw = "10 mx.example.test." } };
            } else if (name == "mx.example.test" && type == DnsClientX.DnsRecordType.A) {
                answers = new[] { new DnsClientX.DnsAnswer { Name = name, Type = type, DataRaw = "192.0.2.10" } };
            } else if (type == DnsClientX.DnsRecordType.PTR) {
                status = ptrStatus;
            }
            return System.Threading.Tasks.Task.FromResult(new DnsClientX.DnsResponse { Status = status, Answers = answers });
        };

        using var guard = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(15));
        await health.Verify("example.test", new[] { HealthCheckType.FCRDNS }, cancellationToken: guard.Token);
        DomainRiskEvidence evidence = DomainRiskProfileBuilder.CollectEvidence(health);

        Assert.Equal(withoutFcrDns, evidence.MailHostsWithoutFcrDns);
        Assert.Equal(ptrState, evidence.PtrState);
    }

    [Theory]
    [InlineData(2, false)]
    [InlineData(3, true)]
    public async System.Threading.Tasks.Task MoreMailHostsThanTheLimitLeaveTheNetworkPartial(int mxHosts, bool capped) {
        var analysis = new IpEnrichmentAnalysis {
            IncludeMxHostAddresses = true,
            IncludeNsHostAddresses = false,
            MaxHostsPerKind = 2,
            QueryOverride = (name, type, _) => {
                name = name.TrimEnd('.');
                if (name == "example.test" && type == DnsClientX.DnsRecordType.MX) {
                    return System.Threading.Tasks.Task.FromResult(Enumerable.Range(1, mxHosts)
                        .Select(i => new DnsClientX.DnsAnswer { Name = name, Type = type, DataRaw = $"10 mx{i}.example.test." }).ToArray());
                }
                return System.Threading.Tasks.Task.FromResult(Array.Empty<DnsClientX.DnsAnswer>());
            }
        };

        await analysis.AnalyzeAsync("example.test", Array.Empty<string>(), new InternalLogger());

        Assert.Equal(capped, analysis.HostsCapped);
    }
}
