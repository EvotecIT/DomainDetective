using DomainDetective.Recommendations;
using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests
{
    public class TestMailTlsRecommendations
    {
        [Fact]
        public void RegistersPositiveCodes()
        {
            var map = new Dictionary<string, RecommendationAdvice>();
            new MailTlsRecommendations().Register(map);
            Assert.Contains(MailTlsCodes.StrongCipherSuite, map.Keys);
            Assert.Contains(MailTlsCodes.CertificateValid, map.Keys);
        }
    }
}
