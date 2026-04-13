using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestDdctApiCertificateTransparencyProvider
{
    [Fact]
    public async Task QueryAsyncHydratesLatestCertificateFromDerEndpoint()
    {
        byte[] der = LoadPemCertificateDer("multi.pem");
        var handler = new HttpStubMessageHandler((request, _) =>
        {
            string pathAndQuery = request.RequestUri!.PathAndQuery;
            if (pathAndQuery.StartsWith("/api/v1/certificates/paged?", StringComparison.Ordinal))
            {
                Assert.Equal("secret", string.Join(",", request.Headers.GetValues("X-DDCT-Api-Key")));
                return Json(HttpStatusCode.OK, new
                {
                    items = new[]
                    {
                        new
                        {
                            sha256Fingerprint = "abc123",
                            matchedName = "www.example.test",
                            firstCtObservedAtUtc = "2026-04-12T10:00:00Z",
                            lastCtObservedAtUtc = "2026-04-12T12:00:00Z",
                            notAfterUtc = "2027-04-12T12:00:00Z"
                        }
                    },
                    limit = 100,
                    offset = 0,
                    nextContinuation = (string?)null,
                    hasMore = false
                });
            }

            if (pathAndQuery == "/api/v1/certificates/abc123/der")
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(der)
                };
            }

            throw new InvalidOperationException("Unexpected URL: " + request.RequestUri);
        });
        using var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("http://127.0.0.1:8080")
        };
        var provider = new DdctApiCertificateTransparencyProvider(
            httpClient,
            new DdctApiCertificateTransparencyProviderOptions
            {
                EndpointUrl = "http://127.0.0.1:8080",
                ApiKey = "secret",
                ScopeName = "internal",
                QueryPageSize = 100,
                MaxPagesPerQuery = 5
            });

        CtCertificateQueryResult result = await provider.QueryAsync(
            CtCertificateQuery.ForExactHostLatest("www.example.test"));

        CtCertificateRecord record = Assert.Single(result.Certificates);
        Assert.Equal(CtProviderProfiles.DdctApiProviderId, result.ProviderId);
        Assert.Equal(CtProviderProfiles.DdctApiProviderId, record.ProviderId);
        Assert.Equal("www.example.test", Assert.Single(result.DiscoveredNames));
        Assert.Equal("abc123", record.ProviderCertificateId);
        Assert.False(result.HasMore);
    }

    [Fact]
    public async Task QueryAsyncUsesObservationPagesForDomainExpansion()
    {
        int requestCount = 0;
        var handler = new HttpStubMessageHandler((request, _) =>
        {
            requestCount++;
            string pathAndQuery = request.RequestUri!.PathAndQuery;
            if (pathAndQuery.Contains("continuation=next-token", StringComparison.Ordinal))
            {
                return Json(HttpStatusCode.OK, new
                {
                    items = new[]
                    {
                        new { matchedName = "mail.example.test" },
                        new { matchedName = "api.example.test" }
                    },
                    limit = 2,
                    offset = 2,
                    nextContinuation = (string?)null,
                    hasMore = false
                });
            }

            return Json(HttpStatusCode.OK, new
            {
                items = new[]
                {
                    new { matchedName = "api.example.test" },
                    new { matchedName = "www.example.test" }
                },
                limit = 2,
                offset = 0,
                nextContinuation = "next-token",
                hasMore = true
            });
        });
        using var httpClient = new HttpClient(handler);
        var provider = new DdctApiCertificateTransparencyProvider(
            httpClient,
            new DdctApiCertificateTransparencyProviderOptions
            {
                EndpointUrl = "http://127.0.0.1:8080",
                MaxPagesPerQuery = 5
            });

        CtCertificateQueryResult result = await provider.QueryAsync(
            CtCertificateQuery.ForDomainExpansion("example.test"));

        Assert.Equal(2, requestCount);
        Assert.Equal(
            new[] { "api.example.test", "mail.example.test", "www.example.test" },
            result.DiscoveredNames);
        Assert.False(result.HasMore);
    }

    private static HttpResponseMessage Json<T>(HttpStatusCode statusCode, T value)
    {
        return new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json")
        };
    }

    private static byte[] LoadPemCertificateDer(string fileName)
    {
        string safeFileName = Path.GetFileName(fileName);
        Assert.Equal(fileName, safeFileName);
        string dataDirectory = Path.Combine(AppContext.BaseDirectory, "Data");
        string pem = File.ReadAllText(Path.Combine(dataDirectory, safeFileName));
        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";
        int start = pem.IndexOf(begin, StringComparison.Ordinal);
        int finish = pem.IndexOf(end, StringComparison.Ordinal);
        Assert.True(start >= 0 && finish > start, "Expected PEM certificate fixture.");
        string base64 = pem.Substring(start + begin.Length, finish - start - begin.Length)
            .Replace("\r", string.Empty)
            .Replace("\n", string.Empty)
            .Trim();
        return Convert.FromBase64String(base64);
    }
}
