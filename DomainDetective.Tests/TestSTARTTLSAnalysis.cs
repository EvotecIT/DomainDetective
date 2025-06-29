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
                Assert.False(analysis.DowngradeDetected[$"localhost:{port}"]);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task StartTlsAdvertisedReturnsTrueIPv6() {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.IPv6Loopback, 0);
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
                await analysis.AnalyzeServer("::1", port, new InternalLogger());
                Assert.True(analysis.ServerResults[$"::1:{port}"]);
                Assert.False(analysis.DowngradeDetected[$"::1:{port}"]);
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
                Assert.False(analysis.DowngradeDetected[$"localhost:{port}"]);
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
                    connectionClosed = await stream.ReadAsync(buffer, 0, 1) == 0;
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
                await writer.WriteLineAsync("250-localhost\r\n250-STARTTLS\r\n250 OK");
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
                await writer.WriteLineAsync("250 localhost");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                var analysis = new STARTTLSAnalysis();
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
        public async Task DetectsDowngradeWhenStartTlsSupportedButNotAdvertised() {
            using var cert = CreateSelfSigned();
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
                var cmd = await reader.ReadLineAsync();
                if (cmd?.StartsWith("STARTTLS", System.StringComparison.OrdinalIgnoreCase) == true) {
                    await writer.WriteLineAsync("220 ready");
                    using var ssl = new System.Net.Security.SslStream(stream);
                    await ssl.AuthenticateAsServerAsync(cert, false, System.Security.Authentication.SslProtocols.Tls12, false);
                    using var sslReader = new System.IO.StreamReader(ssl);
                    await sslReader.ReadLineAsync();
                }
            });

            try {
                var analysis = new STARTTLSAnalysis();
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                Assert.True(analysis.ServerResults[$"localhost:{port}"]);
                Assert.True(analysis.DowngradeDetected[$"localhost:{port}"]);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        private static System.Security.Cryptography.X509Certificates.X509Certificate2 CreateSelfSigned() {
            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            var req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=localhost", rsa, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            var cert = req.CreateSelfSigned(System.DateTimeOffset.Now.AddDays(-1), System.DateTimeOffset.Now.AddDays(30));
            return new System.Security.Cryptography.X509Certificates.X509Certificate2(cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx));
        }
    }
}