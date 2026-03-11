using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestRdapClient
{
    [Fact]
    public async Task ReadsDomainFromLocalFiles()
    {
        var client = new RdapClient("Data/rdap");
        var result = await client.QueryDomainAsync("example.com");
        Assert.NotNull(result);
        Assert.Equal("EXAMPLE.COM", result!.LdhName);
    }

    [Fact]
    public async Task ReadsIpNetworkFromLocalFiles()
    {
        var client = new RdapClient("Data/rdap");
        var result = await client.QueryIpAsync("192.0.2.1");
        Assert.NotNull(result);
        Assert.Equal("192.0.2.0/24", result!.Cidr);
    }

    [Fact]
    public async Task ReadsCidrNetworkFromEncodedLocalFile()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), "dd-rdap-" + Path.GetRandomFileName());
        Directory.CreateDirectory(Path.Combine(tempRoot, "ip"));
        File.WriteAllText(
            Path.Combine(tempRoot, "ip", "192.0.2.0%2F24.json"),
            "{\"cidr\":\"192.0.2.0/24\"}");

        try
        {
            var client = new RdapClient(tempRoot);
            var result = await client.QueryIpAsync("192.0.2.0/24");
            Assert.NotNull(result);
            Assert.Equal("192.0.2.0/24", result!.Cidr);
        }
        finally
        {
            Directory.Delete(tempRoot, recursive: true);
        }
    }

    [Fact]
    public async Task EncodesCidrInHttpRequests()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        string? requestLine = null;
        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true);
            requestLine = await reader.ReadLineAsync();
            string? line;
            do
            {
                line = await reader.ReadLineAsync();
            }
            while (!string.IsNullOrEmpty(line));

            const string body = "{\"startAddress\":\"192.0.2.0\",\"endAddress\":\"192.0.2.255\",\"cidr\":\"192.0.2.0/24\"}";
            var bytes = Encoding.UTF8.GetBytes(body);
            var header = $"HTTP/1.1 200 OK\r\nContent-Type: application/rdap+json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n";
            var headerBytes = Encoding.ASCII.GetBytes(header);
            await stream.WriteAsync(headerBytes, 0, headerBytes.Length);
            await stream.WriteAsync(bytes, 0, bytes.Length);
            await stream.FlushAsync();
        });

        try
        {
            var client = new RdapClient($"http://127.0.0.1:{port}");
            var result = await client.QueryIpAsync("192.0.2.0/24");
            Assert.NotNull(result);
            Assert.Equal("192.0.2.0/24", result!.Cidr);
            Assert.Equal("GET /ip/192.0.2.0%2F24 HTTP/1.1", requestLine);
        }
        finally
        {
            listener.Stop();
            await serverTask;
        }
    }
}
