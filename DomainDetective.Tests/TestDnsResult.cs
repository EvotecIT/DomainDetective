using DnsClientX;
using DomainDetective;

namespace DomainDetective.Tests {
    public class TestDnsResult {
        [Fact]
        public void ConvertFromDnsAnswerCopiesTtl() {
            var answer = new DnsAnswer {
                Name = "example.com",
                TTL = 3600,
                DataRaw = "1.1.1.1",
                Type = DnsRecordType.A
            };

            var result = DnsResult.FromDnsAnswer(answer);

            Assert.Equal(3600, result.Ttl);
            Assert.Equal("example.com", result.Name);
            Assert.Contains("1.1.1.1", result.Data);
        }
    }
}
