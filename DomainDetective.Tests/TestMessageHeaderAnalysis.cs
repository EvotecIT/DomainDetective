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
            var first = analysis.ReceivedHops[0];
            Assert.Equal("internal.example.com", first.FromHost);
            Assert.Equal("mail1.example.com", first.ByHost);
            Assert.NotNull(first.Timestamp);
            Assert.Null(first.HopDelay);
            var second = analysis.ReceivedHops[1];
            Assert.Equal("mail1.example.com", second.FromHost);
            Assert.Equal("192.0.2.1", second.FromIp);
            Assert.Equal("mx.example.net", second.ByHost);
            Assert.Equal("ESMTP", second.With);
            Assert.Equal("abc123", second.Id);
            Assert.Equal("<recipient@example.com>", second.For);
            Assert.NotNull(second.Timestamp);
            Assert.Equal(TimeSpan.FromMinutes(1), second.HopDelay);
            Assert.Equal(TimeSpan.FromMinutes(1), analysis.TotalTransitTime);
            Assert.Equal(TimeSpan.FromMinutes(1), analysis.MaxHopDelay);
            Assert.Equal(TimeSpan.FromMinutes(1), analysis.MinHopDelay);
            Assert.Equal("pass", analysis.DkimResult);
            Assert.Equal("pass", analysis.SpfResult);
            Assert.Equal("pass", analysis.DmarcResult);
            Assert.Equal("pass", analysis.ArcResult);
        }
    }
}
