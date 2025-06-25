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

        [Fact]
        public async Task ResultsDoNotAccumulateAcrossCalls() {
            var listener1 = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener1.Start();
            var port1 = ((System.Net.IPEndPoint)listener1.LocalEndpoint).Port;
            var serverTask1 = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener1.AcceptTcpClientAsync();
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

            var analysis = new OpenRelayAnalysis();
            try {
                await analysis.AnalyzeServer("localhost", port1, new InternalLogger());
                Assert.Single(analysis.ServerResults);
                Assert.True(analysis.ServerResults.ContainsKey($"localhost:{port1}"));
            } finally {
                listener1.Stop();
                await serverTask1;
            }

            var listener2 = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener2.Start();
            var port2 = ((System.Net.IPEndPoint)listener2.LocalEndpoint).Port;
            var serverTask2 = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener2.AcceptTcpClientAsync();
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
                await analysis.AnalyzeServer("localhost", port2, new InternalLogger());
                Assert.Single(analysis.ServerResults);
                Assert.False(analysis.ServerResults.ContainsKey($"localhost:{port1}"));
                Assert.True(analysis.ServerResults[$"localhost:{port2}"] == false);
            } finally {
                listener2.Stop();
                await serverTask2;
            }
        }

        [Fact]
        public async Task AnalyzeServersMultiplePorts() {
            var listener1 = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener1.Start();
            var port1 = ((System.Net.IPEndPoint)listener1.LocalEndpoint).Port;
            var serverTask1 = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener1.AcceptTcpClientAsync();
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

            var listener2 = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener2.Start();
            var port2 = ((System.Net.IPEndPoint)listener2.LocalEndpoint).Port;
            var serverTask2 = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener2.AcceptTcpClientAsync();
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
                await analysis.AnalyzeServers(new[] { "localhost" }, new[] { port1, port2 }, new InternalLogger());
                Assert.Equal(2, analysis.ServerResults.Count);
                Assert.True(analysis.ServerResults[$"localhost:{port1}"]);
                Assert.False(analysis.ServerResults[$"localhost:{port2}"]);
            } finally {
                listener1.Stop();
                listener2.Stop();
                await serverTask1;
                await serverTask2;
            }
        }

        [Fact]
        public async Task CancelsDuringAnalysis() {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new System.Threading.CancellationTokenSource();
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 local ESMTP");
                await reader.ReadLineAsync();
                await System.Threading.Tasks.Task.Delay(System.Threading.Timeout.Infinite, cts.Token).ContinueWith(_ => { });
            }, cts.Token);

            var analysis = new OpenRelayAnalysis();
            var analyzeTask = analysis.AnalyzeServer("localhost", port, new InternalLogger(), cts.Token);
            cts.Cancel();

            await Assert.ThrowsAsync<System.OperationCanceledException>(() => analyzeTask);

            listener.Stop();
            try { await serverTask; } catch (System.Exception) { }
        }
    }
}