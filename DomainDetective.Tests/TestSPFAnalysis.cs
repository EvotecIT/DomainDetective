namespace DomainDetective.Tests {
    public class TestSpfAnalysis {
        [Fact]
        public async Task TestSpfNullsAndExceedDnsLookups() {
            var spfRecord3 = "v=spf1 ip4: include: test.example.pl a:google.com a:test.com ip4: include: test.example.pl include:_spf.salesforce.com include:_spf.google.com include:spf.protection.outlook.com include:_spf-a.example.com include:_spf-b.example.com include:_spf-c.example.com include:_spf-ssg-a.example.com include:spf-a.anotherexample.com ip4:131.107.115.215 ip4:131.107.115.214 ip4:205.248.106.64 ip4:205.248.106.30 ip4:205.248.106.32 ~all";
            var healthCheck6 = new DomainHealthCheck();
            await healthCheck6.CheckSPF(spfRecord3);

            Assert.True(healthCheck6.SpfAnalysis.SpfRecordExists);
            Assert.False(healthCheck6.SpfAnalysis.MultipleSpfRecords);
            Assert.True(healthCheck6.SpfAnalysis.HasNullLookups, "Should have null lookups");
            Assert.True(healthCheck6.SpfAnalysis.ExceedsDnsLookups, "Exceeds lookups should be true, as we expect it over the board");
            Assert.Equal(14, healthCheck6.SpfAnalysis.DnsLookupsCount);
            Assert.False(healthCheck6.SpfAnalysis.MultipleAllMechanisms);
            Assert.False(healthCheck6.SpfAnalysis.ContainsCharactersAfterAll);
            Assert.False(healthCheck6.SpfAnalysis.HasPtrType);
            Assert.True(healthCheck6.SpfAnalysis.StartsCorrectly);
            Assert.True(healthCheck6.SpfAnalysis.InvalidIpSyntax);
        }

        [Fact]
        public async Task TestSpfConstruct() {
            //%{i}._spf.corp.salesforce.com	Pass	This mechanism is used to construct an arbitrary host name that is used for a DNS 'A' record query.
            var spfRecord3 = "v=spf1 include:_spf.google.com include:_spf.salesforce.com exists:%{i}._spf.corp.salesforce.com ~all";
            var healthCheck6 = new DomainHealthCheck();
            await healthCheck6.CheckSPF(spfRecord3);

            Assert.True(healthCheck6.SpfAnalysis.SpfRecordExists);
            Assert.False(healthCheck6.SpfAnalysis.MultipleSpfRecords);
            Assert.True(healthCheck6.SpfAnalysis.HasNullLookups == false);
            Assert.True(healthCheck6.SpfAnalysis.ExceedsDnsLookups == false);
            Assert.True(healthCheck6.SpfAnalysis.MultipleAllMechanisms == false);
            Assert.True(healthCheck6.SpfAnalysis.ContainsCharactersAfterAll == false);
            Assert.True(healthCheck6.SpfAnalysis.HasPtrType == false);
            Assert.True(healthCheck6.SpfAnalysis.StartsCorrectly == true);
            Assert.False(healthCheck6.SpfAnalysis.InvalidIpSyntax);

        }

        [Fact]
        public async Task TestSpfOver255() {
            var spfRecord3 = "v=spf1 ip4:64.20.227.128/28 ip4:208.123.79.32 ip4:208.123.79.1 ip4:208.123.79.2 ip4:208.123.79.3 ip4:208.123.79.4 ip4:208.123.79.5 ip4:208.123.79.6 ip4:208.123.79.7 ip4:208.123.79.8 ip4:208.123.79.15 ip4:208.123.79.14 ip4:208.123.79.13 ip4:208.123.79.12 ip4:208.123.79.11 ip4:208.123.79.10 ip4:208.123.79.9 ip4:208.123.79.16 ip4:208.123.79.17 include:_spf.google.com include:_spf.ladesk.com include:spf.protection.outlook.com include:spf-a.hotmail.com include:_spf-a.microsoft.com include:_spf-b.microsoft.com include:_spf-c.microsoft.com include:_spf-ssg-a.msft.net include:spf-a.hotmail.com include:_spf1-meo.microsoft.com -all";
            var healthCheck6 = new DomainHealthCheck();
            await healthCheck6.CheckSPF(spfRecord3);

            Assert.True(healthCheck6.SpfAnalysis.SpfRecordExists);
            Assert.False(healthCheck6.SpfAnalysis.MultipleSpfRecords);
            Assert.False(healthCheck6.SpfAnalysis.HasNullLookups);
            Assert.True(healthCheck6.SpfAnalysis.ExceedsDnsLookups, "Should exceed DNS lookups due to many includes");
            Assert.False(healthCheck6.SpfAnalysis.MultipleAllMechanisms);
            Assert.False(healthCheck6.SpfAnalysis.ContainsCharactersAfterAll);
            Assert.False(healthCheck6.SpfAnalysis.HasPtrType);
            Assert.True(healthCheck6.SpfAnalysis.StartsCorrectly);
            Assert.True(healthCheck6.SpfAnalysis.ExceedsCharacterLimit, "Should exceed character limit due to long record");
            Assert.False(healthCheck6.SpfAnalysis.InvalidIpSyntax);
        }

        [Fact]
        public async Task TestSpfNotExceedingLookups() {
            var spfRecord3 = "v=spf1 ip4:64.20.227.128/28 ip4:208.123.79.32 ip4:208.123.79.1 ip4:208.123.79.2 ip4:208.123.79.3 ip4:208.123.79.4 ip4:208.123.79.5 ip4:208.123.79.6 ip4:208.123.79.7 ip4:208.123.79.8 ip4:208.123.79.15 ip4:208.123.79.14 ip4:208.123.79.13 ip4:208.123.79.12 ip4:208.123.79.11 ip4:208.123.79.10 ip4:208.123.79.9 ip4:208.123.79.16 ip4:208.123.79.17 include:_spf.google.com include:_spf.ladesk.com -all";
            var healthCheck6 = new DomainHealthCheck();
            await healthCheck6.CheckSPF(spfRecord3);

            Assert.True(healthCheck6.SpfAnalysis.SpfRecordExists);
            Assert.False(healthCheck6.SpfAnalysis.MultipleSpfRecords);
            Assert.False(healthCheck6.SpfAnalysis.HasNullLookups);
            Assert.False(healthCheck6.SpfAnalysis.ExceedsDnsLookups, "Should not exceed DNS lookups due to many includes");
            Assert.False(healthCheck6.SpfAnalysis.MultipleAllMechanisms);
            Assert.False(healthCheck6.SpfAnalysis.ContainsCharactersAfterAll);
            Assert.False(healthCheck6.SpfAnalysis.HasPtrType);
            Assert.True(healthCheck6.SpfAnalysis.StartsCorrectly);
            Assert.True(healthCheck6.SpfAnalysis.ExceedsCharacterLimit, "Should exceed character limit due to long record");
            Assert.False(healthCheck6.SpfAnalysis.InvalidIpSyntax);
        }

        [Fact]
        public async Task QueryDomainBySPF() {
            var healthCheck6 = new DomainHealthCheck();
            await healthCheck6.Verify("evotec.pl", [HealthCheckType.SPF]);

            Assert.True(healthCheck6.SpfAnalysis.SpfRecordExists);
            Assert.False(healthCheck6.SpfAnalysis.MultipleSpfRecords);
            Assert.False(healthCheck6.SpfAnalysis.HasNullLookups);
            Assert.False(healthCheck6.SpfAnalysis.ExceedsDnsLookups);
            Assert.False(healthCheck6.SpfAnalysis.MultipleAllMechanisms);
            Assert.False(healthCheck6.SpfAnalysis.ContainsCharactersAfterAll);
            Assert.False(healthCheck6.SpfAnalysis.HasPtrType);
            Assert.True(healthCheck6.SpfAnalysis.StartsCorrectly);
            Assert.False(healthCheck6.SpfAnalysis.ExceedsCharacterLimit);
        }

        [Fact]
        public async Task TestSpfCheckTwiceDoesNotAccumulate() {
            var spfRecord = "v=spf1 include:_spf.google.com -all";
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckSPF(spfRecord);
            var firstCount = healthCheck.SpfAnalysis.SpfRecords.Count;
            var firstLookups = healthCheck.SpfAnalysis.DnsLookupsCount;

            await healthCheck.CheckSPF(spfRecord);

            Assert.Equal(firstCount, healthCheck.SpfAnalysis.SpfRecords.Count);
            Assert.Equal(firstLookups, healthCheck.SpfAnalysis.DnsLookupsCount);
        }

        [Fact]
        public async Task DetectRedirectModifier() {
            var spfRecord = "v=spf1 ReDiRect=_spf.example.com";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckSPF(spfRecord);

            Assert.True(healthCheck.SpfAnalysis.HasRedirect);
            Assert.Equal("_spf.example.com", healthCheck.SpfAnalysis.RedirectValue);
        }

        [Fact]
        public async Task DetectExpModifier() {
            var spfRecord = "v=spf1 EXP=explanation.domain.tld -all";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckSPF(spfRecord);

            Assert.True(healthCheck.SpfAnalysis.HasExp);
            Assert.Equal("explanation.domain.tld", healthCheck.SpfAnalysis.ExpValue);
        }

        [Fact]
        public async Task CaseInsensitiveMechanisms() {
            var spfRecord = "V=SPF1 INCLUDE:_spf.google.com -ALL";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckSPF(spfRecord);

            Assert.True(healthCheck.SpfAnalysis.StartsCorrectly);
            Assert.Contains("_spf.google.com", healthCheck.SpfAnalysis.IncludeRecords);
            Assert.Equal("-ALL", healthCheck.SpfAnalysis.AllMechanism);
        }

        [Fact]
        public async Task DetectCircularInclude() {
            var healthCheck = new DomainHealthCheck();
            healthCheck.SpfAnalysis.TestSpfRecords["a.example.com"] = "v=spf1 include:b.example.com -all";
            healthCheck.SpfAnalysis.TestSpfRecords["b.example.com"] = "v=spf1 include:a.example.com -all";

            await healthCheck.CheckSPF("v=spf1 include:a.example.com -all");

            Assert.True(healthCheck.SpfAnalysis.CycleDetected);
            Assert.False(healthCheck.SpfAnalysis.ExceedsDnsLookups);
        }

        [Fact]
        public async Task DetectCircularRedirect() {
            var healthCheck = new DomainHealthCheck();
            healthCheck.SpfAnalysis.TestSpfRecords["a.example.com"] = "v=spf1 redirect=b.example.com";
            healthCheck.SpfAnalysis.TestSpfRecords["b.example.com"] = "v=spf1 redirect=a.example.com";

            await healthCheck.CheckSPF("v=spf1 redirect=a.example.com");

            Assert.True(healthCheck.SpfAnalysis.CycleDetected);
            Assert.Equal("a.example.com -> b.example.com -> a.example.com", healthCheck.SpfAnalysis.CyclePath);
        }

        [Fact]
        public async Task RedirectVisitedDomainsTracked() {
            var healthCheck = new DomainHealthCheck();
            healthCheck.SpfAnalysis.TestSpfRecords["a.example.com"] = "v=spf1 redirect=b.example.com";
            healthCheck.SpfAnalysis.TestSpfRecords["b.example.com"] = "v=spf1 redirect=a.example.com";

            await healthCheck.CheckSPF("v=spf1 redirect=a.example.com");

            Assert.Contains("a.example.com", healthCheck.SpfAnalysis.RedirectVisitedDomains);
            Assert.Contains("b.example.com", healthCheck.SpfAnalysis.RedirectVisitedDomains);
        }

        [Fact]
        public async Task PermErrorOnRedirectLoop() {
            var healthCheck = new DomainHealthCheck();
            healthCheck.SpfAnalysis.TestSpfRecords["a.example.com"] = "v=spf1 redirect=b.example.com";
            healthCheck.SpfAnalysis.TestSpfRecords["b.example.com"] = "v=spf1 redirect=a.example.com";

            await healthCheck.CheckSPF("v=spf1 redirect=a.example.com");

            Assert.True(healthCheck.SpfAnalysis.PermError);
        }

        [Fact]
        public async Task DomainEndingWithAllWithoutAllMechanism() {
            var spfRecord = "v=spf1 a:firewall";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckSPF(spfRecord);

            Assert.Null(healthCheck.SpfAnalysis.AllMechanism);
            Assert.False(healthCheck.SpfAnalysis.MultipleAllMechanisms);
            Assert.False(healthCheck.SpfAnalysis.ContainsCharactersAfterAll);
        }

        [Fact]
        public async Task DomainEndingWithAllWithAllMechanism() {
            var spfRecord = "v=spf1 include:firewall -all";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckSPF(spfRecord);

            Assert.Equal("-all", healthCheck.SpfAnalysis.AllMechanism);
            Assert.False(healthCheck.SpfAnalysis.MultipleAllMechanisms);
            Assert.False(healthCheck.SpfAnalysis.ContainsCharactersAfterAll);
        }

        [Fact]
        public async Task ChunkLimitBoundary() {
            var chunk = "v=spf1 " + new string('a', 248);
            var spfRecord = $"\"{chunk}\"";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckSPF(spfRecord);

            Assert.False(healthCheck.SpfAnalysis.ExceedsCharacterLimit);
        }

        [Fact]
        public async Task ChunkLimitExceeded() {
            var chunk = "v=spf1 " + new string('a', 249);
            var spfRecord = $"\"{chunk}\"";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckSPF(spfRecord);

            Assert.True(healthCheck.SpfAnalysis.ExceedsCharacterLimit);
        }

        [Fact]
        public async Task TotalLengthBoundary() {
            var spfRecord = $"\"{new string('a', 255)}\" \"{new string('b', 255)}\" \"cc";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckSPF(spfRecord);

            Assert.False(healthCheck.SpfAnalysis.ExceedsCharacterLimit);
            Assert.False(healthCheck.SpfAnalysis.ExceedsTotalCharacterLimit);
        }

        [Fact]
        public async Task TotalLengthExceeded() {
            var spfRecord = $"\"{new string('a', 255)}\" \"{new string('b', 255)}\" \"ccc";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckSPF(spfRecord);

            Assert.False(healthCheck.SpfAnalysis.ExceedsCharacterLimit);
            Assert.True(healthCheck.SpfAnalysis.ExceedsTotalCharacterLimit);
        }

        [Fact]
        public async Task DetectQuotedInclude() {
            var spfRecord = "v=spf1 include:\"_spf.google.com\" -all";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckSPF(spfRecord);

            Assert.Contains("_spf.google.com", healthCheck.SpfAnalysis.IncludeRecords);
            Assert.Equal("-all", healthCheck.SpfAnalysis.AllMechanism);
        }

        [Fact]
        public async Task DetectMacroRedirect() {
            var spfRecord = "v=spf1 redirect=%{d}.spf.example.com";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckSPF(spfRecord);

            Assert.True(healthCheck.SpfAnalysis.HasRedirect);
            Assert.Equal("%{d}.spf.example.com", healthCheck.SpfAnalysis.RedirectValue);
        }

        [Fact]
        public async Task ValidMacroProducesNoWarnings() {
            var spfRecord = "v=spf1 exists:%{i}.spf.%{d} -all";
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckSPF(spfRecord);

            Assert.Empty(healthCheck.SpfAnalysis.Warnings);
        }

        [Fact]
        public async Task InvalidMacroProducesWarning() {
            var spfRecord = "v=spf1 redirect=%{z}.spf.example.com";
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckSPF(spfRecord);

            Assert.NotEmpty(healthCheck.SpfAnalysis.Warnings);
        }

        [Fact]
        public async Task MacroWithDigitsAndReverseValid() {
            var spfRecord = "v=spf1 redirect=%{d1r}.spf.example.com";
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckSPF(spfRecord);

            Assert.Empty(healthCheck.SpfAnalysis.Warnings);
        }

        [Fact]
        public async Task InvalidMacroSequenceProducesWarning() {
            var spfRecord = "v=spf1 exists:%{drr}.example.com";
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckSPF(spfRecord);

            Assert.NotEmpty(healthCheck.SpfAnalysis.Warnings);
        }

        [Fact]
        public async Task NestedIncludesPopulateResolvedCollections() {
            var healthCheck = new DomainHealthCheck();
            healthCheck.SpfAnalysis.TestSpfRecords["a.example.com"] = "v=spf1 include:b.example.com a:host.test ip4:10.10.10.10 mx:mx.test -all";
            healthCheck.SpfAnalysis.TestSpfRecords["b.example.com"] = "v=spf1 a:sub.test ip6:2001::1 -all";

            await healthCheck.CheckSPF("v=spf1 include:a.example.com -all");

            Assert.Contains("host.test", healthCheck.SpfAnalysis.ResolvedARecords);
            Assert.Contains("sub.test", healthCheck.SpfAnalysis.ResolvedARecords);
            Assert.Contains("mx.test", healthCheck.SpfAnalysis.ResolvedMxRecords);
            Assert.Contains("10.10.10.10", healthCheck.SpfAnalysis.ResolvedIpv4Records);
            Assert.Contains("2001::1", healthCheck.SpfAnalysis.ResolvedIpv6Records);
            Assert.False(healthCheck.SpfAnalysis.InvalidIpSyntax);
        }

        [Fact]
        public async Task ExistsMechanismCountsTowardsDnsLookups() {
            var spfRecord = "v=spf1 exists:example.com -all";
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckSPF(spfRecord);

            Assert.Equal(1, healthCheck.SpfAnalysis.DnsLookupsCount);
            Assert.False(healthCheck.SpfAnalysis.ExceedsDnsLookups);
        }

        [Fact]
        public async Task Rfc7208MultipleDomainExample() {
            var healthCheck = new DomainHealthCheck();
            healthCheck.SpfAnalysis.TestSpfRecords["example.com"] = "v=spf1 -all";
            healthCheck.SpfAnalysis.TestSpfRecords["example.net"] = "v=spf1 -all";

            await healthCheck.CheckSPF("v=spf1 include:example.com include:example.net -all");

            Assert.Equal(2, healthCheck.SpfAnalysis.DnsLookupsCount);
            Assert.False(healthCheck.SpfAnalysis.ExceedsDnsLookups);
        }

        [Fact]
        public async Task EscapedParenthesesHandled() {
            var spfRecord = @"v=spf1 redirect=example.com\(test\)";
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckSPF(spfRecord);

            Assert.True(healthCheck.SpfAnalysis.HasRedirect);
            Assert.Equal("example.com(test)", healthCheck.SpfAnalysis.RedirectValue);
        }

        [Fact]
        public async Task EscapedSpaceHandled() {
            var spfRecord = @"v=spf1 redirect=example.com\ test";
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckSPF(spfRecord);

            Assert.True(healthCheck.SpfAnalysis.HasRedirect);
            Assert.Equal("example.com test", healthCheck.SpfAnalysis.RedirectValue);
        }

        [Fact]
        public async Task CommentsAreIgnored() {
            var spfRecord = "v=spf1 ip4:192.0.2.1 -all (comment)";
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckSPF(spfRecord);

            Assert.Contains("192.0.2.1", healthCheck.SpfAnalysis.Ipv4Records);
            Assert.Equal("-all", healthCheck.SpfAnalysis.AllMechanism);
            Assert.False(healthCheck.SpfAnalysis.InvalidIpSyntax);
        }

        [Fact]
        public async Task InvalidCidrMasksTriggerFlag() {
            var spfRecord = "v=spf1 ip4:192.0.2.1/33 ip6:2001::1/129 -all";
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckSPF(spfRecord);

            Assert.True(healthCheck.SpfAnalysis.InvalidIpSyntax);
        }

        [Fact]
        public async Task UnrecognizedTokenCaptured() {
            var spfRecord = "v=spf1 unknown:example.com -all";
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckSPF(spfRecord);

            Assert.Contains("unknown:example.com", healthCheck.SpfAnalysis.UnknownMechanisms);
        }

        [Fact]
        public async Task VersionTagExcludedFromUnknownMechanisms() {
            var spfRecord = "v=spf1 -all";
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckSPF(spfRecord);

            Assert.DoesNotContain("v=spf1", healthCheck.SpfAnalysis.UnknownMechanisms);
        }

        [Fact]
        public async Task GetFlattenedSpfResolvesIncludes() {
            var healthCheck = new DomainHealthCheck();
            healthCheck.SpfAnalysis.TestSpfRecords["a.example.com"] = "v=spf1 ip4:192.0.2.1 -all";

            await healthCheck.CheckSPF("v=spf1 include:a.example.com -all");

            var flattened = await healthCheck.SpfAnalysis.GetFlattenedSpf();

            Assert.Equal("v=spf1 ip4:192.0.2.1 -all", flattened);
        }

        [Fact]
        public async Task GetFlattenedSpfWarnsWhenTooLong() {
            var record = "v=spf1 " + string.Join(" ", Enumerable.Range(0, 40).Select(i => $"ip4:192.0.2.{i}")) + " -all";
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckSPF(record);

            var flattened = await healthCheck.SpfAnalysis.GetFlattenedSpf();

            Assert.Contains("Flattened SPF record exceeds", healthCheck.SpfAnalysis.Warnings.First());
            Assert.Equal(record, flattened);
        }

        [Fact]
        public async Task GetFlattenedIpAddressesReturnsIps() {
            var healthCheck = new DomainHealthCheck();
            healthCheck.SpfAnalysis.TestSpfRecords["a.example.com"] = "v=spf1 ip4:192.0.2.3 -all";

            await healthCheck.CheckSPF("v=spf1 include:a.example.com ip4:192.0.2.1 -all");

            var ips = await healthCheck.SpfAnalysis.GetFlattenedIpAddresses();

            Assert.Contains("192.0.2.1", ips);
            Assert.Contains("192.0.2.3", ips);
        }

        [Fact]
        public async Task GetFlattenedIpAddressesWarnsOnTooManyLookups() {
            var record = "v=spf1 " + string.Join(" ", Enumerable.Range(0, 12).Select(i => $"include:a{i}.example.com")) + " -all";
            var healthCheck = new DomainHealthCheck();
            foreach (var i in Enumerable.Range(0, 12)) {
                healthCheck.SpfAnalysis.TestSpfRecords[$"a{i}.example.com"] = "v=spf1 ip4:192.0.2.1 -all";
            }

            await healthCheck.CheckSPF(record);

            _ = await healthCheck.SpfAnalysis.GetFlattenedIpAddresses();

            Assert.Contains(
                healthCheck.SpfAnalysis.Warnings,
                w => w.Contains("lookup limit", StringComparison.OrdinalIgnoreCase));
        }
    }
}