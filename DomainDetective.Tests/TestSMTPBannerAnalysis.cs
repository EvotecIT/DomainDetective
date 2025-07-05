using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestSMTPBannerAnalysis {
        [Fact]
        public async Task BannerMatchesExpectations() {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 mail.example.com ESMTP Postfix");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                var analysis = new SMTPBannerAnalysis { ExpectedHostname = "mail.example.com", ExpectedSoftware = "Postfix" };
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                var result = analysis.ServerResults[$"localhost:{port}"];
                Assert.Equal("220 mail.example.com ESMTP Postfix", result.Banner);
                Assert.True(result.HostnameMatch);
                Assert.True(result.SoftwareMatch);
                Assert.True(result.StartsWith220);
                Assert.True(result.ContainsDomain);
                Assert.True(result.ValidFormat);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task NonMatchingBanner() {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 other ESMTP Exim");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                var analysis = new SMTPBannerAnalysis { ExpectedHostname = "mail.example.com", ExpectedSoftware = "Postfix" };
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                var result = analysis.ServerResults[$"localhost:{port}"];
                Assert.False(result.HostnameMatch);
                Assert.False(result.SoftwareMatch);
                Assert.True(result.StartsWith220);
                Assert.True(result.ContainsDomain);
                Assert.True(result.ValidFormat);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Theory]
        [InlineData("500 invalid")]
        [InlineData("220nospace")]
        [InlineData("220 example..com ESMTP")] 
        public async Task MalformedBanner(string banner) {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync(banner);
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                var logger = new InternalLogger();
                var warnings = new System.Collections.Generic.List<LogEventArgs>();
                logger.OnWarningMessage += (_, e) => warnings.Add(e);
                var analysis = new SMTPBannerAnalysis();
                await analysis.AnalyzeServer("localhost", port, logger);
                var result = analysis.ServerResults[$"localhost:{port}"];
                Assert.False(result.ValidFormat);
                Assert.Contains(warnings, w => w.FullMessage.Contains("RFC 5321"));
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task ResultsDoNotAccumulateAcrossCalls() {
            var listener1 = new TcpListener(IPAddress.Loopback, 0);
            listener1.Start();
            var port1 = ((IPEndPoint)listener1.LocalEndpoint).Port;
            var serverTask1 = Task.Run(async () => {
                using var client = await listener1.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 a");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            var analysis = new SMTPBannerAnalysis();
            try {
                await analysis.AnalyzeServer("localhost", port1, new InternalLogger());
                Assert.Single(analysis.ServerResults);
            } finally {
                listener1.Stop();
                await serverTask1;
            }

            var listener2 = new TcpListener(IPAddress.Loopback, 0);
            listener2.Start();
            var port2 = ((IPEndPoint)listener2.LocalEndpoint).Port;
            var serverTask2 = Task.Run(async () => {
                using var client = await listener2.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 b");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                await analysis.AnalyzeServer("localhost", port2, new InternalLogger());
                Assert.Single(analysis.ServerResults);
                Assert.False(analysis.ServerResults.ContainsKey($"localhost:{port1}"));
                Assert.True(analysis.ServerResults.ContainsKey($"localhost:{port2}"));
            } finally {
                listener2.Stop();
                await serverTask2;
            }
        }

        [Fact]
        public async Task TruncatesLongBanner() {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                var longBanner = "220 " + new string('A', 600);
                await writer.WriteLineAsync(longBanner);
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                var logger = new InternalLogger();
                var warnings = new System.Collections.Generic.List<LogEventArgs>();
                logger.OnWarningMessage += (_, e) => warnings.Add(e);
                var analysis = new SMTPBannerAnalysis();
                await analysis.AnalyzeServer("localhost", port, logger);
                var result = analysis.ServerResults[$"localhost:{port}"];
                Assert.Equal(510, result.Banner!.Length);
                Assert.Contains(warnings, w => w.FullMessage.Contains("truncated"));
            } finally {
                listener.Stop();
                await serverTask;
            }
        }
    }
}
