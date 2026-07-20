namespace DomainDetective.Tests {
    public class TestZoneTransferAnalysis {
        private static byte[] EncodeName(string name) {
            using var stream = new System.IO.MemoryStream();
            foreach (string label in name.Split('.')) {
                byte[] bytes = System.Text.Encoding.ASCII.GetBytes(label);
                stream.WriteByte((byte)bytes.Length);
                stream.Write(bytes, 0, bytes.Length);
            }
            stream.WriteByte(0);
            return stream.ToArray();
        }

        private static void WriteUInt16(System.IO.Stream stream, ushort value) {
            stream.WriteByte((byte)(value >> 8));
            stream.WriteByte((byte)value);
        }

        private static void WriteUInt32(System.IO.Stream stream, uint value) {
            stream.WriteByte((byte)(value >> 24));
            stream.WriteByte((byte)(value >> 16));
            stream.WriteByte((byte)(value >> 8));
            stream.WriteByte((byte)value);
        }

        private static byte[] BuildMessage(ushort id, byte rcode, ushort answerType) {
            using var message = new System.IO.MemoryStream();
            WriteUInt16(message, id);
            WriteUInt16(message, (ushort)(0x8400 | rcode));
            WriteUInt16(message, 1);
            WriteUInt16(message, answerType == ushort.MaxValue ? (ushort)0 : (ushort)1);
            WriteUInt16(message, 0);
            WriteUInt16(message, 0);
            byte[] zone = EncodeName("example.com");
            message.Write(zone, 0, zone.Length);
            WriteUInt16(message, 252);
            WriteUInt16(message, 1);
            if (answerType != ushort.MaxValue) {
                message.Write(zone, 0, zone.Length);
                WriteUInt16(message, answerType);
                WriteUInt16(message, 1);
                WriteUInt32(message, 60);
                byte[] rdata;
                if (answerType == 6) {
                    using var soa = new System.IO.MemoryStream();
                    byte[] primary = EncodeName("ns1.example.com");
                    byte[] responsible = EncodeName("hostmaster.example.com");
                    soa.Write(primary, 0, primary.Length);
                    soa.Write(responsible, 0, responsible.Length);
                    WriteUInt32(soa, 1);
                    WriteUInt32(soa, 3600);
                    WriteUInt32(soa, 600);
                    WriteUInt32(soa, 86400);
                    WriteUInt32(soa, 60);
                    rdata = soa.ToArray();
                } else {
                    rdata = new byte[] { 192, 0, 2, 1 };
                }
                WriteUInt16(message, (ushort)rdata.Length);
                message.Write(rdata, 0, rdata.Length);
            }
            byte[] msg = message.ToArray();
            var resp = new byte[msg.Length + 2];
            resp[0] = (byte)(msg.Length >> 8);
            resp[1] = (byte)(msg.Length & 0xFF);
            System.Buffer.BlockCopy(msg, 0, resp, 2, msg.Length);
            return resp;
        }

        private static byte[] BuildSoa(ushort id) => BuildMessage(id, 0, 6);
        private static byte[] BuildAnswer(ushort id) => BuildMessage(id, 0, 1);
        private static byte[] BuildError(ushort id) => BuildMessage(id, 5, ushort.MaxValue);

        private static async System.Threading.Tasks.Task ReadExactlyAsync(System.Net.Sockets.NetworkStream stream, byte[] buffer, int offset, int count) {
            while (count > 0) {
                var read = await stream.ReadAsync(buffer, offset, count);
                if (read == 0) {
                    throw new System.IO.EndOfStreamException();
                }

                offset += read;
                count -= read;
            }
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
                await ReadExactlyAsync(stream, buffer, 0, 2);
                int len = buffer[0] << 8 | buffer[1];
                if (len > 0) { await ReadExactlyAsync(stream, buffer, 0, len); }
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
                await ReadExactlyAsync(stream, buffer, 0, 2);
                int len = buffer[0] << 8 | buffer[1];
                if (len > 0) { await ReadExactlyAsync(stream, buffer, 0, len); }
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
                await ReadExactlyAsync(stream, buffer, 0, 2);
                int len = buffer[0] << 8 | buffer[1];
                if (len > 0) { await ReadExactlyAsync(stream, buffer, 0, len); }
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
                await ReadExactlyAsync(stream, buffer, 0, 2);
                int len = buffer[0] << 8 | buffer[1];
                if (len > 0) { await ReadExactlyAsync(stream, buffer, 0, len); }
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
