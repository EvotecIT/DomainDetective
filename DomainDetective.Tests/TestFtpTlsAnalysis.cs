using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using DomainDetective.Helpers;
using Xunit;

namespace DomainDetective.Tests;

public class TestFtpTlsAnalysis {
    [Fact]
    public async Task CertificateInventoryCaptureAcceptsExplicitFtpsEndpoint() {
        using X509Certificate2 certificate = CreateSelfSigned("localhost");
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Task server = Task.Run(async () => {
            using TcpClient client = await listener.AcceptTcpClientAsync();
            using NetworkStream network = client.GetStream();
            using var reader = new StreamReader(network, Encoding.ASCII, false, 1024, true);
            using var writer = new StreamWriter(network, Encoding.ASCII, 1024, true) { AutoFlush = true, NewLine = "\r\n" };
            await writer.WriteLineAsync("220 Ready");
            Assert.Equal("AUTH TLS", await reader.ReadLineAsync());
            await writer.WriteLineAsync("234 AUTH TLS accepted");
            using var ssl = new SslStream(network, false);
            await ssl.AuthenticateAsServerAsync(certificate, false, SslProtocols.Tls12, false);
        });

        try {
            var options = new CertificateInventoryCaptureOptions {
                IncludeApexHttps = false,
                IncludeWwwHttps = false,
                IncludeMxHosts = false,
                PersistSnapshot = false,
                FtpTlsTimeout = TimeSpan.FromSeconds(5)
            };
            options.AdditionalEndpoints.Add($"ftps-explicit://localhost:{port}");

            CertificateInventoryCaptureResult capture = await new CertificateInventoryCapture().CaptureAsync(
                Array.Empty<string>(),
                options,
                new InternalLogger());

            Assert.Equal(1, capture.FtpTlsEndpointCount);
            Assert.Equal(1, capture.ProbedFtpTlsCount);
            CertificateInventoryEntry entry = Assert.Single(capture.Snapshot.Entries);
            Assert.Equal("FTPS-EXPLICIT", entry.Service);
            Assert.Equal("ftps-explicit", entry.Scheme);
            Assert.Equal(IPAddress.Loopback.ToString(), entry.RemoteAddress);
            Assert.NotNull(entry.ObservedAtUtc);
            Assert.Equal("default", entry.ProbeVantage);
            Assert.NotNull(entry.CertificateThumbprint);
            Assert.False(entry.ChainComplete);
        } finally {
            listener.Stop();
            await server;
        }
    }

    [Fact]
    public async Task ExplicitFtpsUsesAuthTlsBeforeHandshake() {
        using X509Certificate2 certificate = CreateSelfSigned("localhost");
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        string? receivedCommand = null;
        Task server = Task.Run(async () => {
            using TcpClient client = await listener.AcceptTcpClientAsync();
            using NetworkStream network = client.GetStream();
            using var reader = new StreamReader(network, Encoding.ASCII, false, 1024, true);
            using var writer = new StreamWriter(network, Encoding.ASCII, 1024, true) { AutoFlush = true, NewLine = "\r\n" };
            await writer.WriteLineAsync("220-local fixture");
            await writer.WriteLineAsync("220 Ready");
            receivedCommand = await reader.ReadLineAsync();
            await writer.WriteLineAsync("234 AUTH TLS accepted");
            using var ssl = new SslStream(network, false);
            await ssl.AuthenticateAsServerAsync(certificate, false, SslProtocols.Tls12, false);
        });

        try {
            var analysis = new FtpTlsAnalysis { Timeout = TimeSpan.FromSeconds(5) };
            FtpTlsResult result = await analysis.AnalyzeAsync(
                new FtpTlsEndpoint("localhost", port, FtpTlsMode.Explicit) { ConnectAddress = IPAddress.Loopback },
                new InternalLogger());

            Assert.Equal("AUTH TLS", receivedCommand);
            Assert.True(result.TlsNegotiated);
            Assert.Equal(FtpTlsMode.Explicit, result.Mode);
            Assert.NotNull(result.Certificate);
            Assert.False(result.CertificateValid);
            Assert.False(result.ChainValid);
            Assert.NotEmpty(result.ChainErrors);
            Assert.Equal(IPAddress.Loopback.ToString(), result.Connection.RemoteAddress);
            Assert.Equal("220 Ready", result.Greeting[result.Greeting.Count - 1]);
            Assert.Equal("234 AUTH TLS accepted", result.AuthTlsResponse[result.AuthTlsResponse.Count - 1]);
        } finally {
            listener.Stop();
            await server;
        }
    }

    [Fact]
    public async Task ImplicitFtpsStartsTlsImmediately() {
        using X509Certificate2 certificate = CreateSelfSigned("localhost");
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Task server = Task.Run(async () => {
            using TcpClient client = await listener.AcceptTcpClientAsync();
            using var ssl = new SslStream(client.GetStream(), false);
            await ssl.AuthenticateAsServerAsync(certificate, false, SslProtocols.Tls12, false);
        });

        try {
            var analysis = new FtpTlsAnalysis { Timeout = TimeSpan.FromSeconds(5) };
            FtpTlsResult result = await analysis.AnalyzeAsync(
                new FtpTlsEndpoint("localhost", port, FtpTlsMode.Implicit) { ConnectAddress = IPAddress.Loopback },
                new InternalLogger());

            Assert.True(result.TlsNegotiated);
            Assert.Equal(FtpTlsMode.Implicit, result.Mode);
            Assert.Empty(result.Greeting);
            Assert.Empty(result.AuthTlsResponse);
            Assert.NotNull(result.Certificate);
        } finally {
            listener.Stop();
            await server;
        }
    }

    [Fact]
    public async Task ExplicitFtpsDoesNotHandshakeWhenAuthTlsIsRejected() {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Task server = Task.Run(async () => {
            using TcpClient client = await listener.AcceptTcpClientAsync();
            using NetworkStream network = client.GetStream();
            using var reader = new StreamReader(network, Encoding.ASCII, false, 1024, true);
            using var writer = new StreamWriter(network, Encoding.ASCII, 1024, true) { AutoFlush = true, NewLine = "\r\n" };
            await writer.WriteLineAsync("220 Ready");
            Assert.Equal("AUTH TLS", await reader.ReadLineAsync());
            await writer.WriteLineAsync("534 TLS unavailable");
        });

        try {
            var analysis = new FtpTlsAnalysis { Timeout = TimeSpan.FromSeconds(5) };
            FtpTlsResult result = await analysis.AnalyzeAsync(
                new FtpTlsEndpoint("localhost", port, FtpTlsMode.Explicit) { ConnectAddress = IPAddress.Loopback },
                new InternalLogger());

            Assert.False(result.TlsNegotiated);
            Assert.Null(result.Certificate);
            Assert.Contains("234", result.FailureReason, StringComparison.OrdinalIgnoreCase);
        } finally {
            listener.Stop();
            await server;
        }
    }

    private static X509Certificate2 CreateSelfSigned(string commonName) {
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(commonName);
        request.CertificateExtensions.Add(san.Build());
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        return CertificateLoaderCompat.LoadPkcs12(certificate.Export(X509ContentType.Pfx));
    }
}
