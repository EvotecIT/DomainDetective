using DnsClientX;
using System;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestDnsTtlAnalysis {
        private static DnsTtlAnalysis Create(int ttl, bool dnssec = false) {
            return new DnsTtlAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (_, type) => {
                    if (type == DnsRecordType.DS && !dnssec) {
                        return Task.FromResult(Array.Empty<DnsAnswer>());
                    }

                    return Task.FromResult(new[] { new DnsAnswer { TTL = ttl, Type = type } });
                }
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

        [Fact]
        public async Task MaxTtlPasses() {
            var analysis = Create(86400);
            await analysis.Analyze("example.com", new InternalLogger());
            Assert.Empty(analysis.Warnings);
        }

        [Fact]
        public async Task WarnsForDnssecZoneBelow3600() {
            var analysis = Create(1800, dnssec: true);
            await analysis.Analyze("example.com", new InternalLogger());
            Assert.Contains(analysis.Warnings, w => w.Contains("DNSSEC-signed"));
        }

        [Fact]
        public async Task NoWarningForNonDnssecZoneBelow3600() {
            var analysis = Create(1800);
            await analysis.Analyze("example.com", new InternalLogger());
            Assert.Empty(analysis.Warnings);
        }
    }
}
