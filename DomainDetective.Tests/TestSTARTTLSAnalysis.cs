namespace DomainDetective.Tests {
    public class TestSTARTTLSAnalysis {
        [Fact]
        public async Task StartTlsAdvertisedReturnsTrue() {
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
                await writer.WriteLineAsync("250-localhost\r\n250-STARTTLS\r\n250 OK");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                var analysis = new STARTTLSAnalysis();
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                Assert.True(analysis.ServerResults[$"localhost:{port}"]);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task StartTlsNotAdvertisedReturnsFalse() {
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
                await writer.WriteLineAsync("250 localhost");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                var analysis = new STARTTLSAnalysis();
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
                await writer.WriteLineAsync("250-localhost\r\n250-STARTTLS\r\n250 OK");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            var analysis = new STARTTLSAnalysis();
            try {
                await analysis.AnalyzeServer("localhost", port1, new InternalLogger());
                Assert.Single(analysis.ServerResults);
                Assert.True(analysis.ServerResults[$"localhost:{port1}"]);
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
                await writer.WriteLineAsync("250 localhost");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                await analysis.AnalyzeServer("localhost", port2, new InternalLogger());
                Assert.Single(analysis.ServerResults);
                Assert.False(analysis.ServerResults.ContainsKey($"localhost:{port1}"));
                Assert.False(analysis.ServerResults[$"localhost:{port2}"]);
            } finally {
                listener2.Stop();
                await serverTask2;
            }
        }

        [Fact]
        public async Task ParsesCapabilitiesCaseInsensitive() {
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
                await writer.WriteLineAsync("250-localhost\r\n250-SIZE 35882577\r\n250-starttls\r\n250 HELP");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                var analysis = new STARTTLSAnalysis();
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                Assert.True(analysis.ServerResults[$"localhost:{port}"]);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task StartTlsDisconnectAfterQuitReturnsTrue() {
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
                await writer.WriteLineAsync("250-localhost\r\n250-STARTTLS\r\n250 OK");
                var line = await reader.ReadLineAsync();
                if (line?.StartsWith("QUIT", System.StringComparison.OrdinalIgnoreCase) == true) {
                    client.Close();
                }
            });

            try {
                var analysis = new STARTTLSAnalysis();
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                Assert.True(analysis.ServerResults[$"localhost:{port}"]);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task ConnectionIsClosedAfterCheck() {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            bool connectionClosed = false;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 local ESMTP");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("250-localhost\r\n250 STARTTLS");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
                try {
                    var buffer = new byte[1];
                    connectionClosed = await stream.ReadAsync(buffer.AsMemory(0, 1)) == 0;
                } catch (System.IO.IOException) {
                    connectionClosed = true;
                }
            });

            try {
                var analysis = new STARTTLSAnalysis();
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                var ipProps = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
                bool anyEstablished = ipProps.GetActiveTcpConnections().Any(c =>
                    (c.LocalEndPoint.Port == port || c.RemoteEndPoint.Port == port) &&
                    c.State == System.Net.NetworkInformation.TcpState.Established);
                Assert.True(connectionClosed);
                Assert.False(anyEstablished);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }
    }
}
