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

        [Fact]
        public void OneTimestampCannotEstablishTransitDuration() {
            var analysis = new MessageHeaderAnalysis();
            analysis.Parse("From: sender@example.org\r\nReceived: from sender.example by mx.example with ESMTP; Wed, 17 Jun 2026 12:00:00 +0000\r\n");
            Assert.Single(analysis.ReceivedHops);
            Assert.Null(analysis.TotalTransitTime);
            Assert.Null(analysis.ReceivedHops[0].HopDelay);
        }

        [Fact]
        public void UndatedHopDoesNotHideClockSkewBetweenObservedTimestamps() {
            var analysis = new MessageHeaderAnalysis();
            analysis.Parse("Received: from middle.example by destination.example; Wed, 17 Jun 2026 12:00:00 +0000\r\n"
                + "Received: from source.example by middle.example\r\n"
                + "Received: from origin.example by source.example; Wed, 17 Jun 2026 12:05:00 +0000\r\n");
            Assert.Null(analysis.TotalTransitTime);
            Assert.True(analysis.HasClockSkew);
            Assert.All(analysis.ReceivedHops, hop => Assert.Null(hop.HopDelay));
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void UndatedRouteEndpointCannotEstablishTotalTransit(bool oldestUndated) {
            const string datedEarly = "Received: from first.example by second.example; Wed, 17 Jun 2026 12:00:00 +0000\r\n";
            const string datedLate = "Received: from second.example by third.example; Wed, 17 Jun 2026 12:05:00 +0000\r\n";
            const string undated = "Received: from origin.example by first.example\r\n";
            var analysis = new MessageHeaderAnalysis();
            analysis.Parse(oldestUndated ? datedLate + datedEarly + undated : undated + datedLate + datedEarly);
            Assert.Equal(3, analysis.ReceivedHops.Count);
            Assert.Null(analysis.TotalTransitTime);
        }

        [Fact]
        public void OmittedRouteHopCannotEstablishTotalTransit() {
            var analysis = new MessageHeaderAnalysis();
            analysis.Parse("Received: from second.example by third.example; Wed, 17 Jun 2026 12:05:00 +0000\r\n"
                + "Received: from first.example by second.example; Wed, 17 Jun 2026 12:00:00 +0000\r\n"
                + "Received: from origin.example by first.example; Wed, 17 Jun 2026 11:50:00 +0000\r\n",
                new MessageHeaderAnalysisOptions { MaximumReceivedHops = 2 });
            Assert.Equal(1, analysis.OmittedReceivedHops);
            Assert.Null(analysis.TotalTransitTime);
        }

        [Fact]
        public void UndatedInteriorHopStillAllowsEndpointSpan() {
            var analysis = new MessageHeaderAnalysis();
            analysis.Parse("Received: from middle.example by destination.example; Wed, 17 Jun 2026 12:05:00 +0000\r\n"
                + "Received: from source.example by middle.example\r\n"
                + "Received: from origin.example by source.example; Wed, 17 Jun 2026 12:00:00 +0000\r\n");
            Assert.Equal(TimeSpan.FromMinutes(5), analysis.TotalTransitTime);
            Assert.All(analysis.ReceivedHops, hop => Assert.Null(hop.HopDelay));
        }
    }
}
