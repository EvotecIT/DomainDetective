namespace DomainDetective.Tests {
    public class TestSpfAnalysis {
        [Fact]
        public async Task TestSpfNullsAndExceedDnsLookups() {
            var spfRecord3 = "v=spf1 ip4: include: test.example.pl a:google.com a:test.com ip4: include: test.example.pl include:_spf.salesforce.com include:_spf.google.com include:spf.protection.outlook.com include:_spf-a.example.com include:_spf-b.example.com include:_spf-c.example.com include:_spf-ssg-a.example.com include:spf-a.anotherexample.com ip4:131.107.115.215 ip4:131.107.115.214 ip4:205.248.106.64 ip4:205.248.106.30 ip4:205.248.106.32 ~all";
            var healthCheck6 = new DomainHealthCheck();
            await healthCheck6.CheckSPF(spfRecord3);

            Assert.True(healthCheck6.SpfAnalysis.SpfRecordExists);
            Assert.False(healthCheck6.SpfAnalysis.MultipleSpfRecords);
            Assert.True(healthCheck6.SpfAnalysis.HasNullLookups == true);
            Assert.True(healthCheck6.SpfAnalysis.ExceedsDnsLookups == true, "Exceeds lookups should be true, as we expect it over the board");
            Assert.True(healthCheck6.SpfAnalysis.DnsLookupsCount == 13, "DNS lookups should be 13, as we did it on purpose and got: " + healthCheck6.SpfAnalysis.DnsLookupsCount);
            Assert.True(healthCheck6.SpfAnalysis.MultipleAllMechanisms == false);
            Assert.True(healthCheck6.SpfAnalysis.ContainsCharactersAfterAll == false);
            Assert.True(healthCheck6.SpfAnalysis.HasPtrType == false);
            Assert.True(healthCheck6.SpfAnalysis.StartsCorrectly == true);
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

        }

        [Fact]
        public async Task TestSpfOver255() {
            var spfRecord3 = "v=spf1 ip4:64.20.227.128/28 ip4:208.123.79.32 ip4:208.123.79.1 ip4:208.123.79.2 ip4:208.123.79.3 ip4:208.123.79.4 ip4:208.123.79.5 ip4:208.123.79.6 ip4:208.123.79.7 ip4:208.123.79.8 ip4:208.123.79.15 ip4:208.123.79.14 ip4:208.123.79.13 ip4:208.123.79.12 ip4:208.123.79.11 ip4:208.123.79.10 ip4:208.123.79.9 ip4:208.123.79.16 ip4:208.123.79.17 include:_spf.google.com include:_spf.ladesk.com -all";
            var healthCheck6 = new DomainHealthCheck();
            await healthCheck6.CheckSPF(spfRecord3);

            Assert.True(healthCheck6.SpfAnalysis.SpfRecordExists);
            Assert.False(healthCheck6.SpfAnalysis.MultipleSpfRecords);
            Assert.True(healthCheck6.SpfAnalysis.HasNullLookups == false);
            Assert.True(healthCheck6.SpfAnalysis.ExceedsDnsLookups == true);
            Assert.True(healthCheck6.SpfAnalysis.MultipleAllMechanisms == false);
            Assert.True(healthCheck6.SpfAnalysis.ContainsCharactersAfterAll == false);
            Assert.True(healthCheck6.SpfAnalysis.HasPtrType == false);
            Assert.True(healthCheck6.SpfAnalysis.StartsCorrectly == true);
            Assert.True(healthCheck6.SpfAnalysis.ExceedsCharacterLimit == true);
        }

        [Fact]
        public async Task QueryDomainBySPF() {
            var healthCheck6 = new DomainHealthCheck();
            await healthCheck6.Verify("evotec.pl", [HealthCheckType.SPF]);

            Assert.True(healthCheck6.SpfAnalysis.SpfRecordExists);
            Assert.False(healthCheck6.SpfAnalysis.MultipleSpfRecords);
            Assert.True(healthCheck6.SpfAnalysis.HasNullLookups == false);
            Assert.True(healthCheck6.SpfAnalysis.ExceedsDnsLookups == false);
            Assert.True(healthCheck6.SpfAnalysis.MultipleAllMechanisms == false);
            Assert.True(healthCheck6.SpfAnalysis.ContainsCharactersAfterAll == false);
            Assert.True(healthCheck6.SpfAnalysis.HasPtrType == false);
            Assert.True(healthCheck6.SpfAnalysis.StartsCorrectly == true);
            Assert.True(healthCheck6.SpfAnalysis.ExceedsCharacterLimit == false);
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
    }
}
