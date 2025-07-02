using DnsClientX;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestTyposquattingAnalysis {
        [Fact]
        public async Task DetectsActiveVariant() {
            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (name == "examp1e.com" && type == DnsRecordType.A) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } });
                    }
                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
            };

            await analysis.Analyze("example.com", new InternalLogger());

            Assert.Contains("examp1e.com", analysis.Variants);
            Assert.Contains("examp1e.com", analysis.ActiveDomains);
        }

        [Fact]
        public async Task HealthCheckRunsTyposquatting() {
            var hc = new DomainHealthCheck();
            hc.TyposquattingAnalysis.QueryDnsOverride = (_, _) => Task.FromResult(System.Array.Empty<DnsAnswer>());
            await hc.VerifyTyposquatting("example.com");
            Assert.NotEmpty(hc.TyposquattingAnalysis.Variants);
        }

        [Fact]
        public async Task UsesPublicSuffixForMultiLabelTld() {
            var hc = new DomainHealthCheck();
            hc.TyposquattingAnalysis.QueryDnsOverride = (_, _) => Task.FromResult(System.Array.Empty<DnsAnswer>());

            await hc.TyposquattingAnalysis.Analyze("foo.example.co.uk", new InternalLogger());

            Assert.Contains("foo.examp1e.co.uk", hc.TyposquattingAnalysis.Variants);
        }

        [Fact]
        public async Task LevenshteinThresholdLimitsVariants() {
            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                LevenshteinThreshold = 0
            };

            await analysis.Analyze("example.com", new InternalLogger());

            Assert.Empty(analysis.Variants);
        }

        [Fact]
        public async Task DetectsHomoglyphCharacters() {
            var analysis = new TyposquattingAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                DetectHomoglyphs = true
            };

            await analysis.Analyze("ex\u0430mple.com", new InternalLogger());

            Assert.True(analysis.ContainsHomoglyphs);
        }
    }
}
