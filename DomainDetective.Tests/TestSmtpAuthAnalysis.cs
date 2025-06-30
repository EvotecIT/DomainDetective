using System.Collections.Generic;

namespace DomainDetective.Tests {
    public class TestSmtpAuthAnalysis {
        [Fact]
        public async Task DetectsLoginAndPlain() {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 local ESMTP");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("250-localhost");
                await writer.WriteLineAsync("250-AUTH LOGIN PLAIN");
                await writer.WriteLineAsync("250 OK");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                var analysis = new SmtpAuthAnalysis();
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                var mechs = analysis.ServerMechanisms[$"localhost:{port}"];
                Assert.Contains("LOGIN", mechs);
                Assert.Contains("PLAIN", mechs);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task ParsesAuthEqualsNotation() {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 local ESMTP");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("250-localhost");
                await writer.WriteLineAsync("250-AUTH=PLAIN LOGIN");
                await writer.WriteLineAsync("250 OK");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                var analysis = new SmtpAuthAnalysis();
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                var mechs = analysis.ServerMechanisms[$"localhost:{port}"];
                Assert.Contains("LOGIN", mechs);
                Assert.Contains("PLAIN", mechs);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task WarnsWhenAuthWithoutEightBitMime() {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 local ESMTP");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("250-localhost");
                await writer.WriteLineAsync("250-AUTH LOGIN");
                await writer.WriteLineAsync("250 OK");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                var logger = new InternalLogger();
                var warnings = new List<LogEventArgs>();
                logger.OnWarningMessage += (_, e) => warnings.Add(e);
                var analysis = new SmtpAuthAnalysis();
                await analysis.AnalyzeServer("localhost", port, logger);
                Assert.Contains(warnings, w => w.FullMessage.Contains("8BITMIME"));
            } finally {
                listener.Stop();
                await serverTask;
            }
        }
    }
}
