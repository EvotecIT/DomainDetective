using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests {
    public class TestSmtpBannerNarrative {
        [Fact]
        public void NarrativeSummarizesBanner() {
            var analysis = new SMTPBannerAnalysis { Subject = "localhost:25", ExpectedHostname = "mail.example.com" };
            analysis.ServerResults["localhost:25"] = new SMTPBannerAnalysis.BannerResult {
                Banner = "220 mail.example.com ESMTP",
                HostnameMatch = true,
                TlsAdvertised = true
            };

            var sections = SmtpBannerNarrative.Build(analysis);
            Assert.Contains("localhost:25 banner: 220 mail.example.com ESMTP", sections.Highlights);
            Assert.Contains("Hostname matches expected mail.example.com.", sections.Highlights);
            Assert.Contains("TLS advertised in banner.", sections.Highlights);
        }
    }
}

