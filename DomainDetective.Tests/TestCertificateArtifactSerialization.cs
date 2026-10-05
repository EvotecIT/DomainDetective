using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;
using DomainDetective.Helpers;
using DomainDetective.Reports.Artifacts;

namespace DomainDetective.Tests;

public class TestCertificateArtifactSerialization {
    [Fact]
    public void RunCoordinator_WritesCertificatesAndChainsForAllTlsAnalyses() {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=artifact.example", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var health = new DomainHealthCheck();
        foreach (var analysis in new MailTlsAnalysis[] { health.SmtpTlsAnalysis, health.ImapTlsAnalysis, health.Pop3TlsAnalysis }) {
            var result = new MailTlsAnalysis.TlsResult { Certificate = certificate };
            result.Chain.Add(certificate);
            analysis.ServerResults.Add("mail.example:443", result);
        }
        health.CertificateAnalysis.Certificate = certificate;
        health.CertificateAnalysis.Chain.Add(certificate);
        health.BimiAnalysis.TrustedRoots.Add(certificate);
        var directory = Path.Combine(Path.GetTempPath(), "dd-certificate-artifacts-" + Guid.NewGuid().ToString("N"));
        try {
            using var coordinator = RunCoordinator.Begin("example.com", new InternalLogger(false), directory);
            var runDirectory = coordinator.End(health);
            using var scan = JsonDocument.Parse(File.ReadAllText(Path.Combine(runDirectory, "scan.json")));
            var artifact = scan.RootElement.GetProperty("health");
            foreach (var name in new[] { "SmtpTlsAnalysis", "ImapTlsAnalysis", "Pop3TlsAnalysis" }) {
                var result = artifact.GetProperty(name).GetProperty("ServerResults").GetProperty("mail.example:443");
                AssertCertificate(result.GetProperty("Certificate"), certificate);
                AssertCertificate(result.GetProperty("Chain")[0], certificate);
            }
            AssertCertificate(artifact.GetProperty("CertificateAnalysis").GetProperty("Certificate"), certificate);
            AssertCertificate(artifact.GetProperty("CertificateAnalysis").GetProperty("Chain")[0], certificate);
            AssertCertificate(artifact.GetProperty("BimiAnalysis").GetProperty("TrustedRoots")[0], certificate);
            Assert.True(File.Exists(Path.Combine(runDirectory, "metrics.json")));
        } finally {
            if (Directory.Exists(directory)) {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public void HealthCheckJson_PreservesFailuresAndOmitsRuntimeServices() {
        var health = new DomainHealthCheck();
        health.OutboundAddressResolver = (_, _) => Task.FromResult<System.Collections.Generic.IReadOnlyList<IPAddress>>(Array.Empty<IPAddress>());
        health.SmtpTlsAnalysis.OutboundAddressResolver = health.OutboundAddressResolver;
        health.CertificateAnalysis.OutboundAddressResolver = health.OutboundAddressResolver;
        using var http = new HttpClient();
        http.DefaultRequestHeaders.Add("Authorization", "private-runtime-header");
        health.MTASTSAnalysis.HttpClient = http;
        health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new InvalidOperationException("must not execute");
        Exception failure;
        try {
            throw new InvalidOperationException("probe failed", new IOException("peer closed"));
        } catch (Exception error) {
            failure = error;
        }
        failure.Data["runtime"] = new object();
        health.IPNeighborAnalysis.Errors.Add(failure);
        health.IPNeighborAnalysis.Errors.Add(new AggregateException(failure, new IOException("second peer closed")));
        using var json = JsonDocument.Parse(health.ToJson());
        var root = json.RootElement;
        Assert.False(root.TryGetProperty("OutboundAddressResolver", out _));
        Assert.False(root.TryGetProperty("HttpClientFactory", out _));
        Assert.False(root.GetProperty("MTASTSAnalysis").TryGetProperty("HttpClient", out _));
        var serializedError = root.GetProperty("IPNeighborAnalysis").GetProperty("Errors")[0];
        Assert.Equal("probe failed", serializedError.GetProperty("Message").GetString());
        Assert.Equal(typeof(InvalidOperationException).FullName, serializedError.GetProperty("Type").GetString());
        Assert.Equal("peer closed", serializedError.GetProperty("InnerException").GetProperty("Message").GetString());
        Assert.False(serializedError.TryGetProperty("TargetSite", out _));
        Assert.False(serializedError.TryGetProperty("Data", out _));
        var aggregate = root.GetProperty("IPNeighborAnalysis").GetProperty("Errors")[1];
        Assert.Equal("second peer closed", aggregate.GetProperty("InnerExceptions")[1].GetProperty("Message").GetString());
        Assert.DoesNotContain("private-runtime-header", json.RootElement.GetRawText());
    }

    [Fact]
    public void UnavailableCertificates_SerializeAsNull() {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=disposed.example", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        certificate.Dispose();
        var result = new FtpTlsResult { Certificate = certificate };
        result.Chain.Add(certificate);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(result, JsonOptions.Default));
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("Certificate").ValueKind);
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("Chain")[0].ValueKind);
    }

    private static void AssertCertificate(JsonElement json, X509Certificate2 certificate) {
        Assert.Equal(certificate.Subject, json.GetProperty("Subject").GetString());
        Assert.Equal(certificate.Issuer, json.GetProperty("Issuer").GetString());
        Assert.Equal(certificate.Thumbprint, json.GetProperty("Thumbprint").GetString());
        Assert.Equal(certificate.SerialNumber, json.GetProperty("SerialNumber").GetString());
        Assert.Equal(certificate.NotBefore.ToUniversalTime(), json.GetProperty("NotBefore").GetDateTime());
        Assert.Equal(certificate.NotAfter.ToUniversalTime(), json.GetProperty("NotAfter").GetDateTime());
        Assert.False(json.TryGetProperty("Handle", out _));
        Assert.False(json.TryGetProperty("PrivateKey", out _));
    }
}
