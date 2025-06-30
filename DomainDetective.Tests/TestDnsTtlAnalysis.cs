using DnsClientX;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestDnsTtlAnalysis {
        private static DnsTtlAnalysis Create(int ttl) {
            return new DnsTtlAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (_, type) => Task.FromResult(new[] { new DnsAnswer { TTL = ttl, Type = type } })
            };
        }

        [Fact]
        public async Task WarnsOnShortTtl() {
            var analysis = Create(100);
            await analysis.Analyze("example.com", new InternalLogger());
            Assert.Contains(analysis.Warnings, w => w.Contains("shorter"));
        }

        [Fact]
        public async Task WarnsOnLongTtl() {
            var analysis = Create(1000000);
            await analysis.Analyze("example.com", new InternalLogger());
            Assert.Contains(analysis.Warnings, w => w.Contains("exceeds"));
        }

        [Fact]
        public async Task WarnsBelowLowerBound() {
            var analysis = Create(299);
            await analysis.Analyze("example.com", new InternalLogger());
            Assert.Contains(analysis.Warnings, w => w.Contains("shorter"));
        }

        [Fact]
        public async Task WarnsAboveUpperBound() {
            var analysis = Create(86401);
            await analysis.Analyze("example.com", new InternalLogger());
            Assert.Contains(analysis.Warnings, w => w.Contains("exceeds"));
        }

        [Fact]
        public async Task NoWarningsInRange() {
            var analysis = Create(3600);
            await analysis.Analyze("example.com", new InternalLogger());
            Assert.Empty(analysis.Warnings);
        }
    }
}
