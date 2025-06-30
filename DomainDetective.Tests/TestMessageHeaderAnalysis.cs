using System.IO;

namespace DomainDetective.Tests {
    public class TestMessageHeaderAnalysis {
        [Fact]
        public void ParseMessageHeaders() {
            var raw = File.ReadAllText(Path.Combine("Data", "sample-headers.txt"));
            var analysis = new MessageHeaderAnalysis();
            analysis.Parse(raw, new InternalLogger());

            Assert.Equal("sender@example.com", analysis.From);
            Assert.Equal("recipient@example.com", analysis.To);
            Assert.Equal("Test Message", analysis.Subject);
            Assert.NotNull(analysis.Date);
            Assert.Equal(2, analysis.ReceivedChain.Count);
            Assert.Equal("pass", analysis.DkimResult);
            Assert.Equal("pass", analysis.SpfResult);
            Assert.Equal("pass", analysis.DmarcResult);
            Assert.Equal("pass", analysis.ArcResult);
        }
    }
}
