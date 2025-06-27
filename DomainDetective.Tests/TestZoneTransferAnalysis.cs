namespace DomainDetective.Tests {
    public class TestZoneTransferAnalysis {
        private static byte[] BuildResponse(bool allow) {
            var header = new byte[12];
            header[3] = allow ? (byte)0x00 : (byte)0x05; // rcode
            if (allow) {
                header[7] = 1; // answer count
            }
            var len = (ushort)header.Length;
            var resp = new byte[len + 2];
            resp[0] = (byte)(len >> 8);
            resp[1] = (byte)(len & 0xFF);
            System.Buffer.BlockCopy(header, 0, resp, 2, header.Length);
            return resp;
        }

        [Fact]
        public async Task DetectOpenZoneTransfer() {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                var buffer = new byte[512];
                await stream.ReadAsync(buffer, 0, 2);
                int len = buffer[0] << 8 | buffer[1];
                if (len > 0) { await stream.ReadAsync(buffer, 0, len); }
                var resp = BuildResponse(true);
                await stream.WriteAsync(resp, 0, resp.Length);
            });

            try {
                var analysis = new ZoneTransferAnalysis();
                await analysis.AnalyzeServers("example.com", new[] { "localhost:" + port }, new InternalLogger());
                Assert.True(analysis.ServerResults["localhost:" + port]);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task DetectClosedZoneTransfer() {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                var buffer = new byte[512];
                await stream.ReadAsync(buffer, 0, 2);
                int len = buffer[0] << 8 | buffer[1];
                if (len > 0) { await stream.ReadAsync(buffer, 0, len); }
                var resp = BuildResponse(false);
                await stream.WriteAsync(resp, 0, resp.Length);
            });

            try {
                var analysis = new ZoneTransferAnalysis();
                await analysis.AnalyzeServers("example.com", new[] { "localhost:" + port }, new InternalLogger());
                Assert.False(analysis.ServerResults["localhost:" + port]);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }
    }
}
