using System;
using System.Collections.Generic;
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
    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(601)]
    public async Task RejectsInvalidTimeoutBeforeOpeningAConnection(int timeoutSeconds) {
        var analysis = new FtpTlsAnalysis { Timeout = TimeSpan.FromSeconds(timeoutSeconds) };

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => analysis.AnalyzeAsync(
            new FtpTlsEndpoint("localhost", 21, FtpTlsMode.Explicit),
            new InternalLogger()));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(2)]
    public void RejectsUndefinedTlsMode(int mode) {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new FtpTlsEndpoint("localhost", 21, (FtpTlsMode)mode));
    }

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
            Assert.Equal("IPv4", entry.RemoteAddressFamily);
            Assert.NotNull(entry.ObservedAtUtc);
            Assert.True(entry.ObservedAtUtc <= capture.Snapshot.CapturedAtUtc);
            Assert.Equal("default", entry.ProbeVantage);
            Assert.NotNull(entry.CertificateThumbprint);
            Assert.Contains("localhost", entry.SubjectAlternativeNames, StringComparer.OrdinalIgnoreCase);
            Assert.False(entry.ChainComplete);
        } finally {
            listener.Stop();
            await server;
        }
    }

    [Fact]
    public async Task ExplicitFtpsParticipatesInGlobalTargetAllocation() {
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
            int httpsTargetsObserved = -1;
            var capture = new CertificateInventoryCapture {
                HttpsProbeOverride = (targets, _, _, _) => {
                    httpsTargetsObserved = targets.Count;
                    return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(Array.Empty<CertificateMonitor.Entry>());
                }
            };
            var options = new CertificateInventoryCaptureOptions {
                IncludeApexHttps = true,
                IncludeWwwHttps = false,
                IncludeMxHosts = false,
                PersistSnapshot = false,
                MaxTargets = 1,
                FtpTlsTimeout = TimeSpan.FromSeconds(5)
            };
            options.AdditionalEndpoints.Add($"ftps-explicit://localhost:{port}");

            CertificateInventoryCaptureResult result = await capture.CaptureAsync(
                new[] { "example.com" },
                options,
                new InternalLogger());

            Assert.Equal(0, httpsTargetsObserved);
            Assert.Equal(0, result.HttpsEndpointCount);
            Assert.Equal(1, result.FtpTlsEndpointCount);
            Assert.Equal(1, result.ProbedFtpTlsCount);
            Assert.Equal(1, result.HttpsTargetCountDroppedByLimit);
            Assert.Equal(0, result.FtpTlsTargetCountDroppedByLimit);
            Assert.Equal("FTPS-EXPLICIT", Assert.Single(result.Snapshot.Entries).Service);
            Assert.Contains(result.TargetDecisionDiagnostics, diagnostic =>
                diagnostic.Service == "HTTPS" && diagnostic.Reason == "max-targets");
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
            DateTimeOffset startedAtUtc = DateTimeOffset.UtcNow;
            FtpTlsResult result = await analysis.AnalyzeAsync(
                new FtpTlsEndpoint("localhost", port, FtpTlsMode.Explicit) { ConnectAddress = IPAddress.Loopback },
                new InternalLogger());
            DateTimeOffset completedAtUtc = DateTimeOffset.UtcNow;

            Assert.Equal("AUTH TLS", receivedCommand);
            Assert.True(result.TlsNegotiated);
            Assert.Equal(FtpTlsMode.Explicit, result.Mode);
            Assert.NotNull(result.Certificate);
            Assert.Contains("localhost", result.CertificateDnsNames, StringComparer.OrdinalIgnoreCase);
            Assert.Null(result.SanParsingError);
            Assert.False(result.CertificateValid);
            Assert.False(result.ChainValid);
            Assert.NotEmpty(result.ChainErrors);
            Assert.Equal(IPAddress.Loopback.ToString(), result.Connection.RemoteAddress);
            Assert.Equal("IPv4", result.Connection.RemoteAddressFamily);
            Assert.InRange(result.ObservedAtUtc, startedAtUtc, completedAtUtc);
            Assert.Equal("220 Ready", result.Greeting[result.Greeting.Count - 1]);
            Assert.Equal("234 AUTH TLS accepted", result.AuthTlsResponse[result.AuthTlsResponse.Count - 1]);
        } finally {
            listener.Stop();
            await server;
        }
    }

    [Fact]
    public async Task ExplicitFtpsWaitsForServiceReadyAfterPreliminaryGreeting() {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        string? receivedCommand = null;
        Task server = Task.Run(async () => {
            using TcpClient client = await listener.AcceptTcpClientAsync();
            using NetworkStream network = client.GetStream();
            using var reader = new StreamReader(network, Encoding.ASCII, false, 1024, true);
            using var writer = new StreamWriter(network, Encoding.ASCII, 1024, true) { AutoFlush = true, NewLine = "\r\n" };
            await writer.WriteLineAsync("120 Service ready in a moment");
            await writer.WriteLineAsync("220 Ready");
            receivedCommand = await reader.ReadLineAsync();
            await writer.WriteLineAsync("534 TLS unavailable in fixture");
        });

        try {
            var analysis = new FtpTlsAnalysis { Timeout = TimeSpan.FromSeconds(5) };
            FtpTlsResult result = await analysis.AnalyzeAsync(
                new FtpTlsEndpoint("localhost", port, FtpTlsMode.Explicit) { ConnectAddress = IPAddress.Loopback },
                new InternalLogger());

            Assert.Equal("AUTH TLS", receivedCommand);
            Assert.Equal(
                new[] { "120 Service ready in a moment", "220 Ready" },
                result.Greeting);
            Assert.Contains("234", result.FailureReason, StringComparison.OrdinalIgnoreCase);
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
