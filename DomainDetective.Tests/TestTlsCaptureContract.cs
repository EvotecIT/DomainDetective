using System.IO;
using System.Net.Security;
using System.Reflection;
using System.Security.Authentication;
using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

[Collection("Performance proxy environment")]
public class TestTlsCaptureContract {
#if NET8_0_OR_GREATER
    [Fact]
    public async Task KnownHttpRouteReusesOnlyTheMatchingTargetProtocol() {
        string[] names = { "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy" };
        var previous = names.ToDictionary(name => name, Environment.GetEnvironmentVariable);
        var previousProxy = System.Net.Http.HttpClient.DefaultProxy;
        try {
            foreach (var name in names) { Environment.SetEnvironmentVariable(name, null); }
            System.Net.Http.HttpClient.DefaultProxy = new WebProxy();
            int connects = 0;
            using var analysis = new CertificateAnalysis {
                CaptureTlsDetails = true,
                OutboundAddressResolver = (_, _) => {
                    Interlocked.Increment(ref connects);
                    return Task.FromResult<System.Collections.Generic.IReadOnlyList<IPAddress>>(Array.Empty<IPAddress>());
                }
            };
            using var stream = new NegotiatedStream();
            var target = new Uri("https://fixture.example");
            typeof(CertificateAnalysis).GetMethod("CaptureHttpTlsNegotiation", BindingFlags.NonPublic | BindingFlags.Instance)!
                .Invoke(analysis, new object[] { stream, target, 443 });
            var probe = typeof(CertificateAnalysis).GetMethod("ProbeProtocolSupport", BindingFlags.NonPublic | BindingFlags.Instance)!;
            using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await (Task)probe.Invoke(analysis, new object[] { target, 443, new InternalLogger(), guard.Token })!;
            Assert.Equal(3, connects);
            Assert.True(analysis.SupportsTls12);
            await (Task)probe.Invoke(analysis, new object[] { new Uri("https://other.example"), 443, new InternalLogger(), guard.Token })!;
            Assert.Equal(7, connects);
            Assert.False(analysis.SupportsTls12);
        } finally {
            System.Net.Http.HttpClient.DefaultProxy = previousProxy;
            foreach (var name in names) { Environment.SetEnvironmentVariable(name, previous[name]); }
        }
    }
#endif

    [Theory]
    [InlineData(false, "fixture.example")]
    [InlineData(true, "fixture.example")]
    [InlineData(false, "[fe80::1%12]")]
    [InlineData(true, "[fe80::1%12]")]
    public async Task DirectNegotiationDoesNotEstablishProxyProtocolSupport(bool detailsPhase, string authority) {
        string[] names = { "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy" };
        var previous = names.ToDictionary(name => name, Environment.GetEnvironmentVariable);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int requests = 0;
        var connectLines = new System.Collections.Concurrent.ConcurrentBag<string>();
        var server = Task.Run(async () => {
            try {
                while (true) {
                    using var client = await listener.AcceptTcpClientAsync();
                    Interlocked.Increment(ref requests);
                    using var reader = new StreamReader(client.GetStream(), System.Text.Encoding.ASCII, false, 1024, true);
                    connectLines.Add((await reader.ReadLineAsync())!);
                    while (!string.IsNullOrEmpty(await reader.ReadLineAsync())) { }
                    var response = System.Text.Encoding.ASCII.GetBytes("HTTP/1.1 502 No origin connection\r\n\r\n");
                    await client.GetStream().WriteAsync(response, 0, response.Length);
                }
            } catch (SocketException) { }
            catch (ObjectDisposedException) { }
        });
        try {
            foreach (var name in names) { Environment.SetEnvironmentVariable(name, null); }
            Environment.SetEnvironmentVariable("HTTPS_PROXY", $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}");
            using var analysis = new CertificateAnalysis {
                CaptureTlsDetails = true, CaptureExtendedMetadata = false, CaptureCtMetadata = false, SkipRevocation = true
            };
            using var key = System.Security.Cryptography.RSA.Create();
            key.KeySize = 2048;
            var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=fixture.example", key,
                System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            if (detailsPhase) { await analysis.AnalyzeCertificate(certificate); }
            using var stream = new NegotiatedStream();
            typeof(CertificateAnalysis).GetMethod("CaptureTlsNegotiation", BindingFlags.NonPublic | BindingFlags.Instance)!
                .Invoke(analysis, new object[] { stream });
            using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            if (detailsPhase) {
                var finalizing = (Task)typeof(CertificateAnalysis).GetMethod("FinalizeCapturedCertificateAsync", BindingFlags.NonPublic | BindingFlags.Instance)!
                    .Invoke(analysis, new object[] { $"https://{authority}", 443, new InternalLogger(), guard.Token })!;
                await Assert.ThrowsAsync<IOException>(() => finalizing);
                Assert.Equal(1, Volatile.Read(ref requests));
            } else {
                await (Task)typeof(CertificateAnalysis).GetMethod("ProbeProtocolSupport", BindingFlags.NonPublic | BindingFlags.Instance)!
                    .Invoke(analysis, new object[] { new Uri($"https://{authority}"), 443, new InternalLogger(), guard.Token })!;
                Assert.Equal(4, Volatile.Read(ref requests));
                Assert.False(analysis.SupportsTls12);
                Assert.False(analysis.ProtocolSupportComplete);
            }
            Assert.All(connectLines, line => Assert.Equal($"CONNECT {authority}:443 HTTP/1.1", line));
        } finally {
            listener.Stop();
            await server;
            foreach (var name in names) { Environment.SetEnvironmentVariable(name, previous[name]); }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NegotiatedDetailsHonorCaptureOption(bool capture) {
        using var analysis = new CertificateAnalysis { CaptureTlsDetails = capture };
        using var stream = new NegotiatedStream();
        typeof(CertificateAnalysis).GetMethod("CaptureTlsNegotiation", BindingFlags.NonPublic | BindingFlags.Instance)!
            .Invoke(analysis, new object[] { stream });
        Assert.Equal(capture ? SslProtocols.Tls12 : SslProtocols.None, analysis.TlsProtocol);
        if (capture) { Assert.Equal(256, analysis.CipherStrength); }
        else { Assert.True(string.IsNullOrEmpty(analysis.CipherSuite)); }
    }

    private sealed class NegotiatedStream : SslStream {
        public NegotiatedStream() : base(new MemoryStream()) { }
        public override SslProtocols SslProtocol => SslProtocols.Tls12;
        public override bool IsAuthenticated => true;
#if !NET10_0_OR_GREATER
        public override CipherAlgorithmType CipherAlgorithm => CipherAlgorithmType.Aes256;
        public override int CipherStrength => 256;
        public override ExchangeAlgorithmType KeyExchangeAlgorithm => ExchangeAlgorithmType.DiffieHellman;
        public override int KeyExchangeStrength => 2048;
        public override HashAlgorithmType HashAlgorithm => HashAlgorithmType.Sha256;
        public override int HashStrength => 256;
#endif
#if NET8_0_OR_GREATER
        public override TlsCipherSuite NegotiatedCipherSuite => TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
#endif
    }
}
