namespace DomainDetective.Tests {
    public class TestWhoisAnalysis {
        [Fact]
        public async Task UnsupportedTldThrows() {
            var whois = new WhoisAnalysis();
            await Assert.ThrowsAsync<UnsupportedTldException>(async () => await whois.QueryWhoisServer("example.unknown"));
        }

        [Fact]
        public async Task MissingTldThrows() {
            var whois = new WhoisAnalysis();
            await Assert.ThrowsAsync<UnsupportedTldException>(async () => await whois.QueryWhoisServer("example"));
        }

        [Fact]
        public async Task QueryFromLocalWhoisServerReadsLargeResponse() {
            var responseBuilder = new System.Text.StringBuilder();
            responseBuilder.AppendLine("Domain Name: example.local");
            for (int i = 0; i < 2000; i++) {
                responseBuilder.AppendLine($"Entry {i}");
            }
            var response = responseBuilder.ToString();

            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response);
            });

            try {
                var whois = new WhoisAnalysis();
                var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (System.Collections.Generic.Dictionary<string, string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                // Ensure thread-safe modification of the internal WHOIS servers collection
                var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var lockObj = lockField?.GetValue(whois);
                Assert.NotNull(lockObj);
                lock (lockObj!) {
                    servers!["local"] = $"localhost:{port}";
                }

                await whois.QueryWhoisServer("example.local");

                Assert.Equal("example.local", whois.DomainName);
                var expected = response.Replace("\r\n", "\n").Replace("\r", "\n");
                var actual = whois.WhoisData.Replace("\r\n", "\n").Replace("\r", "\n");
                Assert.Equal(expected, actual);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task QueryFromLocalWhoisServerReadsLargeResponseCaseInsensitive() {
            var responseBuilder = new System.Text.StringBuilder();
            responseBuilder.AppendLine("Domain Name: example.local");
            for (int i = 0; i < 2000; i++) {
                responseBuilder.AppendLine($"Entry {i}");
            }
            var response = responseBuilder.ToString();

            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response);
            });

            try {
                var whois = new WhoisAnalysis();
                var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (System.Collections.Generic.Dictionary<string, string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                servers!["local"] = $"localhost:{port}";

                await whois.QueryWhoisServer("EXAMPLE.LOCAL");

                Assert.Equal("example.local", whois.DomainName);
                var expected = response.Replace("\r\n", "\n").Replace("\r", "\n");
                var actual = whois.WhoisData.Replace("\r\n", "\n").Replace("\r", "\n");
                Assert.Equal(expected, actual);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task ParsesRegistrarAbuseContactInfo() {
            var response = string.Join("\n", new[] {
                "Domain Name: example.sample",
                "Registrar: Example Registrar",
                "Registrar Abuse Contact Email: abuse@example.com",
                "Registrar Abuse Contact Phone: +1.1234567890",
                $"Registry Expiry Date: {DateTime.UtcNow.AddDays(10):yyyy-MM-dd}",
                "Name Server: ns1.example.sample"
            });

            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response);
            });

            try {
                var whois = new WhoisAnalysis();
                var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (System.Collections.Generic.Dictionary<string, string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var lockObj = lockField?.GetValue(whois);
                Assert.NotNull(lockObj);
                lock (lockObj!) {
                    servers!["sample"] = $"localhost:{port}";
                }

                await whois.QueryWhoisServer("example.sample");

                Assert.Equal("abuse@example.com", whois.RegistrarAbuseEmail);
                Assert.Equal("+1.1234567890", whois.RegistrarAbusePhone);
                Assert.True(whois.ExpiresSoon);
                Assert.False(whois.IsExpired);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task ParsesRegistrarLicense() {
            var response = string.Join("\n", new[] {
                "Domain Name: license.sample",
                "Registrar: Example Registrar",
                "Registrar License: XYZ-123",
                "Name Server: ns1.license.sample"
            });

            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response);
            });

            try {
                var whois = new WhoisAnalysis();
                var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (System.Collections.Generic.Dictionary<string, string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var lockObj = lockField?.GetValue(whois);
                Assert.NotNull(lockObj);
                lock (lockObj!) {
                    servers!["sample"] = $"localhost:{port}";
                }

                await whois.QueryWhoisServer("license.sample");

                Assert.Equal("XYZ-123", whois.RegistrarLicense);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task SetsExpiredFlagWhenDatePast() {
            var response = string.Join("\n", new[] {
                "Domain Name: expired.sample",
                $"Registry Expiry Date: {DateTime.UtcNow.AddDays(-1):yyyy-MM-dd}",
                "Registrar: Example Registrar"
            });

            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response);
            });

            try {
                var whois = new WhoisAnalysis();
                var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (System.Collections.Generic.Dictionary<string, string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var lockObj = lockField?.GetValue(whois);
                Assert.NotNull(lockObj);
                lock (lockObj!) {
                    servers!["sample"] = $"localhost:{port}";
                }

                await whois.QueryWhoisServer("expired.sample");

                Assert.True(whois.IsExpired);
                Assert.False(whois.ExpiresSoon);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task QueryMultipleDomainsConcurrently() {
            var response1 = "Domain Name: example.one";
            var response2 = "Domain Name: example.two";

            var listener1 = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener1.Start();
            var port1 = ((System.Net.IPEndPoint)listener1.LocalEndpoint).Port;
            var serverTask1 = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener1.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response1);
            });

            var listener2 = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener2.Start();
            var port2 = ((System.Net.IPEndPoint)listener2.LocalEndpoint).Port;
            var serverTask2 = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener2.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response2);
            });

            List<WhoisAnalysis> results;
            try {
                var whois = new WhoisAnalysis();
                var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (System.Collections.Generic.Dictionary<string, string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var lockObj = lockField?.GetValue(whois);
                Assert.NotNull(lockObj);
                lock (lockObj!) {
                    servers!["one"] = $"localhost:{port1}";
                    servers!["two"] = $"localhost:{port2}";
                }

                results = await whois.QueryWhoisServers(["example.one", "example.two"]);
            } finally {
                listener1.Stop();
                listener2.Stop();
                await System.Threading.Tasks.Task.WhenAll(serverTask1, serverTask2);
            }

            Assert.Equal(2, results.Count);
            var r1 = results.Single(r => r.DomainName == "example.one");
            var r2 = results.Single(r => r.DomainName == "example.two");
            Assert.Equal(response1, r1.WhoisData.Trim());
            Assert.Equal(response2, r2.WhoisData.Trim());
        }

        [Fact]
        public async Task ParsesRegistrarLockStatus() {
            var response = string.Join("\n", new[] {
                "Domain Name: locked.sample",
                $"Registry Expiry Date: {DateTime.UtcNow.AddDays(60):yyyy-MM-dd}",
                "Domain Status: clientTransferProhibited"
            });

            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response);
            });

            try {
                var whois = new WhoisAnalysis();
                var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (System.Collections.Generic.Dictionary<string, string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var lockObj = lockField?.GetValue(whois);
                Assert.NotNull(lockObj);
                lock (lockObj!) {
                    servers!["sample"] = $"localhost:{port}";
                }

                await whois.QueryWhoisServer("locked.sample");

                Assert.True(whois.RegistrarLocked);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task DetectsPrivacyProtection() {
            var response = string.Join("\n", new[] {
                "Domain Name: privacy.sample",
                "Registrant Name: REDACTED FOR PRIVACY",
                "Registrar: Example Registrar"
            });

            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response);
            });

            try {
                var whois = new WhoisAnalysis();
                var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (System.Collections.Generic.Dictionary<string, string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var lockObj = lockField?.GetValue(whois);
                Assert.NotNull(lockObj);
                lock (lockObj!) {
                    servers!["sample"] = $"localhost:{port}";
                }

                await whois.QueryWhoisServer("privacy.sample");

                Assert.True(whois.PrivacyProtected);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task DetectsNoPrivacyWhenAbsent() {
            var response = string.Join("\n", new[] {
                "Domain Name: noprive.sample",
                "Registrar: Example Registrar"
            });

            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response);
            });

            try {
                var whois = new WhoisAnalysis();
                var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (System.Collections.Generic.Dictionary<string, string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var lockObj = lockField?.GetValue(whois);
                Assert.NotNull(lockObj);
                lock (lockObj!) {
                    servers!["sample"] = $"localhost:{port}";
                }

                await whois.QueryWhoisServer("noprive.sample");

                Assert.False(whois.PrivacyProtected);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task RespectsExpirationWarningThreshold() {
            var response = string.Join("\n", new[] {
                "Domain Name: warn.sample",
                $"Registry Expiry Date: {DateTime.UtcNow.AddDays(15):yyyy-MM-dd}",
                "Registrar: Example Registrar"
            });

            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response);
            });

            try {
                var whois = new WhoisAnalysis { ExpirationWarningThreshold = TimeSpan.FromDays(10) };
                var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (System.Collections.Generic.Dictionary<string, string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var lockObj = lockField?.GetValue(whois);
                Assert.NotNull(lockObj);
                lock (lockObj!) {
                    servers!["sample"] = $"localhost:{port}";
                }

                await whois.QueryWhoisServer("warn.sample");

                Assert.False(whois.ExpiresSoon);
            } finally {
                listener.Stop();
                await serverTask;
            }

            // second query with longer threshold
            listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response);
            });

            try {
                var whois = new WhoisAnalysis { ExpirationWarningThreshold = TimeSpan.FromDays(20) };
                var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (System.Collections.Generic.Dictionary<string, string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var lockObj = lockField?.GetValue(whois);
                Assert.NotNull(lockObj);
                lock (lockObj!) {
                    servers!["sample"] = $"localhost:{port}";
                }

                await whois.QueryWhoisServer("warn.sample");

                Assert.True(whois.ExpiresSoon);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task QueryIpWhoisParsesData() {
            var response = string.Join("\n", new[] {
                "NetRange: 198.51.100.0 - 198.51.100.255",
                "origin: AS64496"
            });

            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response);
            });

            try {
                var whois = new WhoisAnalysis();
                var field = typeof(WhoisAnalysis).GetField("IpWhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (System.Collections.Generic.List<string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                var lockField = typeof(WhoisAnalysis).GetField("_ipWhoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var lockObj = lockField?.GetValue(whois);
                Assert.NotNull(lockObj);
                lock (lockObj!) {
                    servers!.Clear();
                    servers.Add($"127.0.0.1:{port}");
                }

                var (allocation, asn) = await whois.QueryIpWhois("198.51.100.25");

                Assert.Equal("198.51.100.0 - 198.51.100.255", allocation);
                Assert.Equal("AS64496", asn);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task LogsServerAndDomainOnError() {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();

            var logger = new InternalLogger();
            LogEventArgs? eventArgs = null;
            logger.OnErrorMessage += (_, e) => eventArgs = e;

            var whois = new WhoisAnalysis();
            var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var servers = (System.Collections.Generic.Dictionary<string, string>?)field?.GetValue(whois);
            Assert.NotNull(servers);
            var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var lockObj = lockField?.GetValue(whois);
            Assert.NotNull(lockObj);
            lock (lockObj!) {
                servers!["sample"] = $"127.0.0.1:{port}";
            }

            await whois.QueryWhoisServer("example.sample", default);

            Assert.NotNull(eventArgs);
            Assert.Contains($"127.0.0.1:{port}", eventArgs!.FullMessage);
            Assert.Contains("example.sample", eventArgs.FullMessage);
        }
    }
}
