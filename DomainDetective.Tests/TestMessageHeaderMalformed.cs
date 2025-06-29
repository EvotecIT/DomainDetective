using System.IO;

namespace DomainDetective.Tests {
    public class TestMessageHeaderMalformed {
        [Fact]
        public void ParseHeadersWithMalformedLines() {
            var raw = File.ReadAllText("Data/sample-headers-malformed.txt");
            var analysis = new MessageHeaderAnalysis();
            analysis.Parse(raw, new InternalLogger());

            Assert.Equal("sender@example.com", analysis.From);
            Assert.Equal("recipient@example.com", analysis.To);
            Assert.Equal("Malformed Message", analysis.Subject);
            Assert.NotNull(analysis.Date);
            Assert.Single(analysis.ReceivedChain);
            Assert.Equal("pass", analysis.DkimResult);
            Assert.Equal("pass", analysis.SpfResult);
            Assert.Equal("pass", analysis.DmarcResult);
            Assert.Equal("pass", analysis.ArcResult);
        }
    }
}
