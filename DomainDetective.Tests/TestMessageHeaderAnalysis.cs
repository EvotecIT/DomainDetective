using System.IO;

namespace DomainDetective.Tests {
    public class TestMessageHeaderAnalysis {
        [Fact]
        public void ParseMessageHeaders() {
            var raw = File.ReadAllText("Data/sample-headers.txt");
            var analysis = new MessageHeaderAnalysis();
            analysis.Parse(raw, new InternalLogger());

            Assert.Equal("sender@example.com", analysis.From);
            Assert.Equal("recipient@example.com", analysis.To);
            Assert.Equal("Test Message", analysis.Subject);
            Assert.NotNull(analysis.Date);
            Assert.Equal(2, analysis.ReceivedHops.Count);
            var hop = analysis.ReceivedHops[0];
            Assert.Equal("mail1.example.com", hop.FromHost);
            Assert.Equal("192.0.2.1", hop.FromIp);
            Assert.Equal("mx.example.net", hop.ByHost);
            Assert.Equal("ESMTP", hop.With);
            Assert.Equal("abc123", hop.Id);
            Assert.Equal("<recipient@example.com>", hop.For);
            Assert.NotNull(hop.Timestamp);
            Assert.Equal("pass", analysis.DkimResult);
            Assert.Equal("pass", analysis.SpfResult);
            Assert.Equal("pass", analysis.DmarcResult);
            Assert.Equal("pass", analysis.ArcResult);
        }
    }
}
