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
        string? noContinuation = null;
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
                    nextContinuation = noContinuation,
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
        using var httpClient = new HttpClient(handler);
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
        string? noContinuation = null;
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
                    nextContinuation = noContinuation,
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

    [Fact]
    public async Task QueryAsyncReturnsEmptyResultWhenCertificatePageIsMissing()
    {
        var handler = new HttpStubMessageHandler((_, _) => new HttpResponseMessage(HttpStatusCode.NotFound));
        using var httpClient = new HttpClient(handler);
        var provider = new DdctApiCertificateTransparencyProvider(
            httpClient,
            new DdctApiCertificateTransparencyProviderOptions
            {
                EndpointUrl = "http://127.0.0.1:8080"
            });

        CtCertificateQueryResult result = await provider.QueryAsync(
            CtCertificateQuery.ForExactHostLatest("missing.example.test"));

        Assert.Empty(result.Certificates);
        Assert.Empty(result.DiscoveredNames);
        Assert.False(result.HasMore);
        Assert.Empty(result.Diagnostics);
    }

    [Fact]
    public async Task QueryAsyncAddsDiagnosticWhenHistoryHitsConfiguredPageCap()
    {
        byte[] der = LoadPemCertificateDer("multi.pem");
        int page = 0;
        var handler = new HttpStubMessageHandler((request, _) =>
        {
            string pathAndQuery = request.RequestUri!.PathAndQuery;
            if (pathAndQuery.StartsWith("/api/v1/certificates/paged?", StringComparison.Ordinal))
            {
                page++;
                return Json(HttpStatusCode.OK, new
                {
                    items = new[]
                    {
                        new
                        {
                            sha256Fingerprint = "cert-" + page,
                            matchedName = "www.example.test",
                            firstCtObservedAtUtc = "2026-04-12T10:00:00Z",
                            lastCtObservedAtUtc = "2026-04-12T12:00:00Z",
                            notAfterUtc = "2027-04-12T12:00:00Z"
                        }
                    },
                    limit = 1,
                    offset = page - 1,
                    nextContinuation = "token-" + page,
                    hasMore = true
                });
            }

            if (pathAndQuery.StartsWith("/api/v1/certificates/cert-", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(der)
                };
            }

            throw new InvalidOperationException("Unexpected URL: " + request.RequestUri);
        });
        using var httpClient = new HttpClient(handler);
        var provider = new DdctApiCertificateTransparencyProvider(
            httpClient,
            new DdctApiCertificateTransparencyProviderOptions
            {
                EndpointUrl = "http://127.0.0.1:8080",
                QueryPageSize = 1,
                MaxPagesPerQuery = 2
            });

        CtCertificateQueryResult result = await provider.QueryAsync(
            CtCertificateQuery.ForExactHostHistory("www.example.test"));

        Assert.Single(result.Certificates);
        Assert.True(result.HasMore);
        Assert.Contains(result.Diagnostics, message => message.Contains("page cap", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task QueryAsyncUsesBearerAuthorizationHeaderWhenRequested()
    {
        byte[] der = LoadPemCertificateDer("multi.pem");
        string? noContinuation = null;
        var handler = new HttpStubMessageHandler((request, _) =>
        {
            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            Assert.Equal("secret", request.Headers.Authorization?.Parameter);

            string pathAndQuery = request.RequestUri!.PathAndQuery;
            if (pathAndQuery.StartsWith("/api/v1/certificates/paged?", StringComparison.Ordinal))
            {
                return Json(HttpStatusCode.OK, new
                {
                    items = new[]
                    {
                        new
                        {
                            sha256Fingerprint = "bearer123",
                            matchedName = "www.example.test",
                            firstCtObservedAtUtc = "2026-04-12T10:00:00Z",
                            lastCtObservedAtUtc = "2026-04-12T12:00:00Z",
                            notAfterUtc = "2027-04-12T12:00:00Z"
                        }
                    },
                    limit = 100,
                    offset = 0,
                    nextContinuation = noContinuation,
                    hasMore = false
                });
            }

            if (pathAndQuery == "/api/v1/certificates/bearer123/der")
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(der)
                };
            }

            throw new InvalidOperationException("Unexpected URL: " + request.RequestUri);
        });
        using var httpClient = new HttpClient(handler);
        var provider = new DdctApiCertificateTransparencyProvider(
            httpClient,
            new DdctApiCertificateTransparencyProviderOptions
            {
                EndpointUrl = "http://127.0.0.1:8080",
                ApiKey = "secret",
                ApiKeyHeaderName = "Authorization"
            });

        CtCertificateQueryResult result = await provider.QueryAsync(
            CtCertificateQuery.ForExactHostLatest("www.example.test"));

        Assert.Single(result.Certificates);
    }

    [Fact]
    public async Task QueryAsyncThrowsForNonSuccessResponses()
    {
        var handler = new HttpStubMessageHandler((_, _) => new HttpResponseMessage(HttpStatusCode.BadGateway));
        using var httpClient = new HttpClient(handler);
        var provider = new DdctApiCertificateTransparencyProvider(
            httpClient,
            new DdctApiCertificateTransparencyProviderOptions
            {
                EndpointUrl = "http://127.0.0.1:8080"
            });

        HttpRequestException ex = await Assert.ThrowsAsync<HttpRequestException>(() =>
            provider.QueryAsync(CtCertificateQuery.ForExactHostLatest("www.example.test")));

        Assert.Contains("502", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task QueryAsyncRejectsEmptyQueryNames()
    {
        using var httpClient = new HttpClient(new HttpStubMessageHandler((_, _) => throw new InvalidOperationException("HTTP should not be called for empty names.")));
        var provider = new DdctApiCertificateTransparencyProvider(
            httpClient,
            new DdctApiCertificateTransparencyProviderOptions
            {
                EndpointUrl = "http://127.0.0.1:8080"
            });

        await Assert.ThrowsAsync<ArgumentException>(() =>
            provider.QueryAsync(CtCertificateQuery.ForExactHostLatest("   ")));
    }

    [Fact]
    public async Task QueryAsyncClampsRequestedCertificateCountToEffectivePageSize()
    {
        byte[] der = LoadPemCertificateDer("multi.pem");
        int pageRequestCount = 0;
        var handler = new HttpStubMessageHandler((request, _) =>
        {
            string pathAndQuery = request.RequestUri!.PathAndQuery;
            if (pathAndQuery.StartsWith("/api/v1/certificates/paged?", StringComparison.Ordinal))
            {
                pageRequestCount++;
                return Json(HttpStatusCode.OK, new
                {
                    items = new[]
                    {
                        new
                        {
                            sha256Fingerprint = "oversized-page",
                            matchedName = "www.example.test",
                            firstCtObservedAtUtc = "2026-04-12T10:00:00Z",
                            lastCtObservedAtUtc = "2026-04-12T12:00:00Z",
                            notAfterUtc = "2027-04-12T12:00:00Z"
                        }
                    },
                    limit = 500,
                    offset = 0,
                    nextContinuation = "next-token",
                    hasMore = true
                });
            }

            if (pathAndQuery == "/api/v1/certificates/oversized-page/der")
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(der)
                };
            }

            throw new InvalidOperationException("Unexpected URL: " + request.RequestUri);
        });
        using var httpClient = new HttpClient(handler);
        var provider = new DdctApiCertificateTransparencyProvider(
            httpClient,
            new DdctApiCertificateTransparencyProviderOptions
            {
                EndpointUrl = "http://127.0.0.1:8080",
                QueryPageSize = 500,
                MaxPagesPerQuery = 5
            });

        CtCertificateQueryResult result = await provider.QueryAsync(
            new CtCertificateQuery
            {
                Name = "www.example.test",
                QueryKind = CtCertificateQueryKind.ExactHostHistory,
                Operations = CtIngestionOperation.GetCertificateHistory,
                RequireFullCertificate = true,
                PageSize = 600
            });

        Assert.Single(result.Certificates);
        Assert.Equal(1, pageRequestCount);
        Assert.Contains(result.Diagnostics, message => message.Contains("page cap", StringComparison.OrdinalIgnoreCase));
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
        Assert.False(Path.IsPathRooted(safeFileName));
        string dataDirectory = Path.Combine(AppContext.BaseDirectory, "Data");
        string pemPath = Path.GetFullPath(Path.Combine(dataDirectory, safeFileName));
        Assert.StartsWith(Path.GetFullPath(dataDirectory), Path.GetDirectoryName(pemPath) ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        string pem = File.ReadAllText(pemPath);
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
