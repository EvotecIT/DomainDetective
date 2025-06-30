namespace DomainDetective.Tests {
    public class TestZoneTransferAnalysis {
        private static byte[] BuildMessage(ushort id, byte rcode, ushort answerType) {
            var header = new byte[12];
            header[0] = (byte)(id >> 8);
            header[1] = (byte)(id & 0xFF);
            header[2] = 0x80;
            header[3] = rcode;
            header[4] = 0x00;
            header[5] = 0x01;
            header[6] = 0x00;
            header[7] = answerType == ushort.MaxValue ? (byte)0 : (byte)1;
            var list = new System.Collections.Generic.List<byte>(32);
            list.AddRange(header);
            list.Add(0x00);
            list.Add(0x00); list.Add(0xFC);
            list.Add(0x00); list.Add(0x01);
            if (answerType != ushort.MaxValue) {
                list.Add(0x00);
                list.Add((byte)(answerType >> 8));
                list.Add((byte)(answerType & 0xFF));
                list.Add(0x00); list.Add(0x01);
                list.AddRange(new byte[4]);
                list.Add(0x00); list.Add(0x00);
            }
            var msg = list.ToArray();
            var resp = new byte[msg.Length + 2];
            resp[0] = (byte)(msg.Length >> 8);
            resp[1] = (byte)(msg.Length & 0xFF);
            System.Buffer.BlockCopy(msg, 0, resp, 2, msg.Length);
            return resp;
        }

        private static byte[] BuildSoa(ushort id) => BuildMessage(id, 0, 6);
        private static byte[] BuildAnswer(ushort id) => BuildMessage(id, 0, 1);
        private static byte[] BuildError(ushort id) => BuildMessage(id, 5, ushort.MaxValue);

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
                ushort id = (ushort)((buffer[0] << 8) | buffer[1]);
                var start = BuildSoa(id);
                var end = BuildSoa(id);
                await stream.WriteAsync(start, 0, start.Length);
                await stream.WriteAsync(end, 0, end.Length);
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
                ushort id = (ushort)((buffer[0] << 8) | buffer[1]);
                var resp = BuildError(id);
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

        [Fact]
        public async Task DetectOpenZoneTransferLargeZone() {
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
                ushort id = (ushort)((buffer[0] << 8) | buffer[1]);
                var start = BuildSoa(id);
                await stream.WriteAsync(start, 0, start.Length);
                for (int i = 0; i < 1000; i++) {
                    var resp = BuildAnswer(id);
                    await stream.WriteAsync(resp, 0, resp.Length);
                }
                var finalResp = BuildSoa(id);
                await stream.WriteAsync(finalResp, 0, finalResp.Length);
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
        public async Task DetectInvalidZoneTransfer() {
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
                ushort id = (ushort)((buffer[0] << 8) | buffer[1]);
                var start = BuildSoa(id);
                var mid = BuildAnswer(id);
                await stream.WriteAsync(start, 0, start.Length);
                await stream.WriteAsync(mid, 0, mid.Length);
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
