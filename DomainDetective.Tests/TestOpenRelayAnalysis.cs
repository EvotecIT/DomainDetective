namespace DomainDetective.Tests {
    public class TestOpenRelayAnalysis {
        [Fact]
        public async Task OpenRelayServerReturnsTrue() {
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
                await writer.WriteLineAsync("250 hello");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("250 OK");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("250 OK");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                var analysis = new OpenRelayAnalysis();
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                Assert.True(analysis.ServerResults[$"localhost:{port}"]);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task RelayDeniedReturnsFalse() {
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
                await writer.WriteLineAsync("250 hello");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("250 OK");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("550 relay denied");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                var analysis = new OpenRelayAnalysis();
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                Assert.False(analysis.ServerResults[$"localhost:{port}"]);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }
    }
}
