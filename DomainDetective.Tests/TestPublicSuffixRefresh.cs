using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestPublicSuffixRefresh {
        [Fact]
        public async Task UsesCacheWhenFresh() {
            var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(dir);
            var fileContent = File.ReadAllBytes(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "public_suffix_list.dat"));
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream);
                await reader.ReadLineAsync();
                while (!string.IsNullOrEmpty(await reader.ReadLineAsync())) { }
                var header = $"HTTP/1.1 200 OK\r\nContent-Length: {fileContent.Length}\r\n\r\n";
                await stream.WriteAsync(System.Text.Encoding.ASCII.GetBytes(header));
                await stream.WriteAsync(fileContent);
            });
            try {
                var hc = new DomainHealthCheck { CacheDirectory = dir };
                await hc.RefreshPublicSuffixListAsync($"http://localhost:{port}/list.dat", force: true);
                var cache = Path.Combine(dir, "public_suffix_list.dat");
                var firstTime = File.GetLastWriteTimeUtc(cache);
                await hc.RefreshPublicSuffixListAsync($"http://localhost:{port}/list.dat");
                var secondTime = File.GetLastWriteTimeUtc(cache);
                Assert.Equal(firstTime, secondTime);
            } finally {
                listener.Stop();
                await serverTask;
                Directory.Delete(dir, true);
            }
        }
    }
}
