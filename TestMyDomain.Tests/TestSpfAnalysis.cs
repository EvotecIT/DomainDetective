namespace TestMyDomain.Tests {
    public class TestSpfAnalysis {
        [Fact]
        public async Task TestSpfNullsAndExceedDnsLookups() {
            var spfRecord3 = "v=spf1 ip4: include: test.example.pl include:_spf-a.example.com include:_spf-b.example.com include:_spf-c.example.com include:_spf-ssg-a.example.com include:spf-a.anotherexample.com ip4:131.107.115.215 ip4:131.107.115.214 ip4:205.248.106.64 ip4:205.248.106.30 ip4:205.248.106.32 ~all";
            var healthCheck6 = new DomainHealthCheck();
            await healthCheck6.CheckSPF(spfRecord3);

            Assert.True(healthCheck6.SpfAnalysis.SpfRecordExists);
            Assert.False(healthCheck6.SpfAnalysis.MultipleSpfRecords);
            Assert.True(healthCheck6.SpfAnalysis.HasNullLookups == true);
            //Assert.True(healthCheck6.SpfAnalysis.ExceedsDnsLookups == false);
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
            Assert.True(healthCheck6.SpfAnalysis.HasNullLookups == true);
            //Assert.True(healthCheck6.SpfAnalysis.ExceedsDnsLookups == false);
            Assert.True(healthCheck6.SpfAnalysis.MultipleAllMechanisms == false);
            Assert.True(healthCheck6.SpfAnalysis.ContainsCharactersAfterAll == false);
            Assert.True(healthCheck6.SpfAnalysis.HasPtrType == false);
            Assert.True(healthCheck6.SpfAnalysis.StartsCorrectly == true);

        }
    }
}