using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Xunit;
using DomainDetective;

namespace DomainDetective.Tests {
    public class TestBgpValidation {
        [Fact]
        public async Task ValidateServerAsnsWarnsOnMismatch() {
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);

            var analysis = new DnsPropagationAnalysis {
                BgpLookupOverride = (ip, ct) => Task.FromResult<int?>(65001)
            };

            analysis.AddServer(new PublicDnsEntry {
                IPAddress = IPAddress.Parse("1.2.3.4"),
                Country = CountryId.UnitedStates,
                ASN = "65000"
            });

            await analysis.ValidateServerAsnsAsync(logger);

            Assert.Contains(warnings, w => w.FullMessage.Contains("expected ASN"));
        }

        [Fact]
        public async Task ValidateServerAsnsIgnoresMatches() {
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);

            var analysis = new DnsPropagationAnalysis {
                BgpLookupOverride = (ip, ct) => Task.FromResult<int?>(65000)
            };

            analysis.AddServer(new PublicDnsEntry {
                IPAddress = IPAddress.Parse("1.2.3.4"),
                Country = CountryId.UnitedStates,
                ASN = "65000"
            });

            await analysis.ValidateServerAsnsAsync(logger);

            Assert.Empty(warnings);
        }
    }
}

