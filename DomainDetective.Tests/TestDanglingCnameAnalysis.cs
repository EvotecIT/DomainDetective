using DnsClientX;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestDanglingCnameAnalysis {
        private static DanglingCnameAnalysis Create(Func<string, DnsRecordType, Task<DnsAnswer[]>>? overrideFunc = null) {
            return new DanglingCnameAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = overrideFunc
            };
        }

        [Fact]
        public async Task DetectsExistingTarget() {
            var analysis = Create((name, type) => {
                if (type == DnsRecordType.CNAME) {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "alias.service.com" } });
                }
                if (name == "alias.service.com" && type == DnsRecordType.A) {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } });
                }
                return Task.FromResult(Array.Empty<DnsAnswer>());
            });
            await analysis.Analyze("www.example.com", new InternalLogger());

            Assert.True(analysis.CnameRecordExists);
            Assert.False(analysis.IsDangling);
        }

        [Fact]
        public async Task DetectsNxDomain() {
            var analysis = Create((name, type) => {
                if (type == DnsRecordType.CNAME) {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "alias.service.com" } });
                }
                return Task.FromResult(Array.Empty<DnsAnswer>());
            });
            await analysis.Analyze("www.example.com", new InternalLogger());

            Assert.True(analysis.IsDangling);
            Assert.False(analysis.TargetResolves);
        }

        [Fact]
        public async Task DetectsUnclaimedService() {
            var analysis = Create((name, type) => {
                if (type == DnsRecordType.CNAME) {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "site.azurewebsites.net" } });
                }
                return Task.FromResult(Array.Empty<DnsAnswer>());
            });
            await analysis.Analyze("www.example.com", new InternalLogger());

            Assert.True(analysis.UnclaimedService);
        }
    }
}
