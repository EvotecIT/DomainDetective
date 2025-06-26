using DnsClientX;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestAutodiscoverAnalysis {
        [Fact]
        public async Task ParseAutodiscoverRecords() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "0 0 443 autodiscover.example.com", Type = DnsRecordType.SRV },
            };
            var cnames = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "mail.example.com", Type = DnsRecordType.CNAME }
            };
            var analysis = new AutodiscoverAnalysis();
            analysis.QueryDnsOverride = (name, type) => {
                if (type == DnsRecordType.SRV) return Task.FromResult(answers.ToArray());
                if (type == DnsRecordType.CNAME) return Task.FromResult(cnames.ToArray());
                return Task.FromResult(Array.Empty<DnsAnswer>());
            };
            await analysis.Analyze("example.com", new DnsConfiguration(), new InternalLogger());

            Assert.True(analysis.SrvRecordExists);
            Assert.Equal("autodiscover.example.com", analysis.SrvTarget);
            Assert.Equal(443, analysis.SrvPort);
            Assert.True(analysis.AutoconfigCnameExists);
            Assert.Equal("mail.example.com", analysis.AutoconfigTarget);
        }

        [Fact]
        public async Task NoRecordsPresent() {
            var analysis = new AutodiscoverAnalysis();
            analysis.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
            await analysis.Analyze("example.com", new DnsConfiguration(), new InternalLogger());
            Assert.False(analysis.SrvRecordExists);
            Assert.False(analysis.AutoconfigCnameExists);
            Assert.False(analysis.AutodiscoverCnameExists);
        }

    }
}
