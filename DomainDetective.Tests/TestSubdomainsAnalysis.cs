using DnsClientX;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Tests.Fixtures;

namespace DomainDetective.Tests;

public class TestSubdomainsAnalysis
{
    public TestSubdomainsAnalysis()
    {
        PassiveCtSourceClient.ResetSharedStateForTesting();
    }

    private static void AssertExpectedListenerCancellation(Exception exception, CancellationToken token)
    {
        Assert.True(token.IsCancellationRequested, exception.Message);
    }

    [Fact]
    public async Task ParsesCtAndAggregatesSubdomains()
    {
        const string json = @"
[
  { ""issuer_name"": ""Issuer A"", ""entry_timestamp"": ""2020-01-01T00:00:00Z"", ""name_value"": ""a.example.com\nb.example.com\n*.wild.example.com\nexample.com"" },
  { ""issuer_name"": ""Issuer A"", ""entry_timestamp"": ""2020-02-01T00:00:00Z"", ""name_value"": ""a.example.com\nc.example.com"" },
  { ""issuer_name"": ""Issuer B"", ""entry_timestamp"": ""2019-12-31T00:00:00Z"", ""name_value"": ""d.example.com"" }
]";

        var analysis = new SubdomainsAnalysis
        {
            VerifyStillResolves = false,
            QueryOverride = (_, _) => Task.FromResult(json)
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Equal(3, analysis.CertificateObservationCount);
        Assert.Equal(new DateTimeOffset(2019, 12, 31, 0, 0, 0, TimeSpan.Zero), analysis.FirstSeenUtc);
        Assert.Equal(new DateTimeOffset(2020, 2, 1, 0, 0, 0, TimeSpan.Zero), analysis.LastSeenUtc);

        Assert.True(analysis.IssuerCounts.TryGetValue("Issuer A", out var aCount));
        Assert.True(analysis.IssuerCounts.TryGetValue("Issuer B", out var bCount));
        Assert.Equal(2, aCount);
        Assert.Equal(1, bCount);

        var names = analysis.Subdomains.Select(s => s.Name).ToList();
        Assert.Contains("a.example.com", names);
        Assert.Contains("b.example.com", names);
        Assert.Contains("c.example.com", names);
        Assert.Contains("d.example.com", names);
        Assert.Contains("wild.example.com", names);
        Assert.DoesNotContain("example.com", names);

        var a = analysis.Subdomains.Single(s => s.Name == "a.example.com");
        Assert.Equal(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), a.FirstSeenUtc);
        Assert.Equal(new DateTimeOffset(2020, 2, 1, 0, 0, 0, TimeSpan.Zero), a.LastSeenUtc);
    }

    [Fact]
    public async Task DnsVerificationCappedSetsResolutionReduced()
    {
        const string json = @"
[
  { ""issuer_name"": ""Issuer A"", ""entry_timestamp"": ""2020-01-01T00:00:00Z"", ""name_value"": ""x.example.com\ny.example.com\nz.example.com"" }
]";

        var seen = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var analysis = new SubdomainsAnalysis
        {
            VerifyStillResolves = true,
            MaxResolutionChecks = 2,
            ResolutionConcurrency = 2,
            QueryOverride = (_, _) => Task.FromResult(json),
            DnsConfiguration = new DnsConfiguration
            {
                QueryDnsOverride = (name, type) =>
                {
                    var key = name + "|" + type;
                    seen[key] = seen.TryGetValue(key, out var c) ? c + 1 : 1;

                    if (name.Equals("x.example.com", StringComparison.OrdinalIgnoreCase) && type == DnsRecordType.A)
                    {
                        return Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.A, DataRaw = "192.0.2.1" } });
                    }
                    if (name.Equals("y.example.com", StringComparison.OrdinalIgnoreCase) && type == DnsRecordType.AAAA)
                    {
                        return Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.AAAA, DataRaw = "2001:db8::1" } });
                    }
                    return Task.FromResult(Array.Empty<DnsAnswer>());
                }
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.True(analysis.ResolutionReduced);

        var x = analysis.Subdomains.Single(s => s.Name == "x.example.com");
        var y = analysis.Subdomains.Single(s => s.Name == "y.example.com");
        var z = analysis.Subdomains.Single(s => s.Name == "z.example.com");

        Assert.Equal(SubdomainResolutionStatus.Resolves, x.ResolutionStatus);
        Assert.Equal(SubdomainResolutionStatus.Resolves, y.ResolutionStatus);
        Assert.Equal(SubdomainResolutionStatus.Unknown, z.ResolutionStatus);

        Assert.Contains(analysis.Assessments, a => a.Code == SubdomainCodes.ResolutionReduced);

        Assert.Contains(seen.Keys, k => k.StartsWith("x.example.com|", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(seen.Keys, k => k.StartsWith("y.example.com|", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(seen.Keys, k => k.StartsWith("z.example.com|", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task FallsBackToCertSpotterWhenPrimaryPayloadIsMalformed()
    {
        var analysis = new SubdomainsAnalysis
        {
            VerifyStillResolves = false,
            QueryOverride = (url, _) =>
            {
                if (url.Contains("crt.sh", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(@"{ ""ok"": true }");
                }

                return Task.FromResult(@"
[
  { ""id"": ""12345"", ""dns_names"": [""api.example.com"", ""example.com""], ""not_before"": ""2026-01-01T00:00:00Z"", ""not_after"": ""2027-01-01T00:00:00Z"" }
]");
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Contains(analysis.Subdomains, s => s.Name == "api.example.com");
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == SubdomainCodes.CtNoResults);
    }

    [Fact]
    public async Task AiInfrastructureExposureProducesAssessmentWhenEnabled()
    {
        const string json = @"
[
  { ""issuer_name"": ""Issuer A"", ""entry_timestamp"": ""2020-01-01T00:00:00Z"", ""name_value"": ""mlflow.example.com"" }
]";

        var analysis = new SubdomainsAnalysis
        {
            VerifyStillResolves = true,
            DetectAiInfrastructureExposure = true,
            MaxResolutionChecks = 10,
            ResolutionConcurrency = 2,
            QueryOverride = (_, _) => Task.FromResult(json),
            DnsConfiguration = new DnsConfiguration
            {
                QueryDnsOverride = (name, type) =>
                {
                    if (name.Equals("mlflow.example.com", StringComparison.OrdinalIgnoreCase) && type == DnsRecordType.A)
                    {
                        return Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.A, DataRaw = "192.0.2.1" } });
                    }
                    return Task.FromResult(Array.Empty<DnsAnswer>());
                }
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.Contains(analysis.Assessments, a => a.Code == SubdomainCodes.AiInfrastructureExposed);
    }

    [Fact]
    public async Task FallsBackToCertSpotterWhenCrtShFails()
    {
        const string certSpotterJson = @"
[
  { ""id"": ""12345"", ""dns_names"": [""api.example.com"", ""example.com""], ""not_before"": ""2026-01-01T00:00:00Z"", ""not_after"": ""2027-01-01T00:00:00Z"" }
]";

        var analysis = new SubdomainsAnalysis
        {
            VerifyStillResolves = false,
            QueryOverride = (url, _) =>
            {
                if (url.Contains("crt.sh", StringComparison.OrdinalIgnoreCase))
                {
                    throw new HttpRequestException("Simulated crt.sh outage.");
                }

                return Task.FromResult(certSpotterJson);
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Equal(1, analysis.CertificateObservationCount);
        Assert.Contains(analysis.Subdomains, s => s.Name == "api.example.com");
        Assert.DoesNotContain(analysis.Subdomains, s => s.Name == "example.com");
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == SubdomainCodes.CtQueryFailed);
        Assert.Contains(Assert.Single(analysis.Subdomains, s => s.Name == "api.example.com").CtSources, source => source.Equals("certspotter", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task PassiveCtTransientFailuresAdviseRetryLater()
    {
        var analysis = new SubdomainsAnalysis
        {
            VerifyStillResolves = false,
            PassiveCtRetryCount = 0,
            PassiveCtSourceCooldown = TimeSpan.FromSeconds(30),
            QueryOverride = (_, _) => throw new HttpRequestException("HTTP 429 Too Many Requests")
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.False(analysis.QuerySucceeded);
        Assert.NotEmpty(analysis.PassiveCtWarnings);
        Assert.Contains(analysis.PassiveCtWarnings, warning => warning.Contains("check later", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.Assessments, a => a.Code == SubdomainCodes.CtQueryFailed);
    }

    [Fact]
    public async Task PassiveCtInvalidPayloadDoesNotEnterSharedCooldownState()
    {
        var requestCount = 0;
        var server = new TcpListenerFixture((listener, token) => Task.Run(async () =>
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    var clientTask = listener.AcceptTcpClientAsync();
                    var completed = await Task.WhenAny(clientTask, Task.Delay(Timeout.Infinite, token));
                    if (completed != clientTask)
                    {
                        try
                        {
                            await clientTask;
                        }
                        catch (ObjectDisposedException ex) when (token.IsCancellationRequested)
                        {
                            AssertExpectedListenerCancellation(ex, token);
                        }
                        catch (SocketException ex) when (token.IsCancellationRequested)
                        {
                            AssertExpectedListenerCancellation(ex, token);
                        }

                        break;
                    }

                    using var client = await clientTask;
                    Interlocked.Increment(ref requestCount);
                    using var stream = client.GetStream();
                    using var reader = new StreamReader(stream);
                    using var writer = new StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                    string? line;
                    do
                    {
                        line = await reader.ReadLineAsync();
                    } while (!string.IsNullOrEmpty(line));

                    await writer.WriteLineAsync("HTTP/1.1 200 OK");
                    await writer.WriteLineAsync("Content-Type: application/json");
                    await writer.WriteLineAsync("Content-Length: 2");
                    await writer.WriteLineAsync();
                    await writer.WriteAsync("{}");
                }
            }
            catch (ObjectDisposedException ex) when (token.IsCancellationRequested)
            {
                AssertExpectedListenerCancellation(ex, token);
            }
            catch (SocketException ex) when (token.IsCancellationRequested)
            {
                AssertExpectedListenerCancellation(ex, token);
            }
        }, token));
        await server.InitializeAsync();

        try
        {
            var client = new PassiveCtSourceClient();
            var requests = new[] {
                new PassiveCtSourceClient.SourceRequest {
                    SourceName = "crt.sh",
                    Url = $"http://127.0.0.1:{server.Port}/"
                }
            };
            var options = new PassiveCtSourceClient.QueryOptions {
                RetryCount = 0,
                SourceCooldown = TimeSpan.FromSeconds(30),
                PayloadValidator = static payload => payload == "{}" ? "response root element must be an array." : null
            };

            var first = await client.QueryAsync(requests, options, null, new InternalLogger(), CancellationToken.None);
            var second = await client.QueryAsync(requests, options, null, new InternalLogger(), CancellationToken.None);

            Assert.True(first.RetrySuggested);
            Assert.True(second.RetrySuggested);
            Assert.DoesNotContain(first.Warnings, warning => warning.Contains("Next retry after", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(second.Warnings, warning => warning.Contains("cooling down", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(first.Diagnostics, diagnostic => diagnostic.CooldownUntilUtc.HasValue);
            Assert.DoesNotContain(second.Diagnostics, diagnostic => string.Equals(diagnostic.State, "CoolingDown", StringComparison.OrdinalIgnoreCase));
            Assert.Equal(2, requestCount);
        }
        finally
        {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task RestoredPassiveCtCooldownSkipsNetworkQueryUntilCooldownExpires()
    {
        var requestCount = 0;
        var server = new TcpListenerFixture((listener, token) => Task.Run(async () =>
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    var clientTask = listener.AcceptTcpClientAsync();
                    var completed = await Task.WhenAny(clientTask, Task.Delay(Timeout.Infinite, token));
                    if (completed != clientTask)
                    {
                        break;
                    }

                    using var client = await clientTask;
                    Interlocked.Increment(ref requestCount);
                }
            }
            catch (ObjectDisposedException ex) when (token.IsCancellationRequested)
            {
                AssertExpectedListenerCancellation(ex, token);
            }
            catch (SocketException ex) when (token.IsCancellationRequested)
            {
                AssertExpectedListenerCancellation(ex, token);
            }
        }, token));
        await server.InitializeAsync();

        try
        {
            CertificateInventoryCapture.RestorePassiveCtSharedCooldownState(new[]
            {
                new PassiveCtDiagnosticEntry
                {
                    SourceName = "crt.sh",
                    CooldownUntilUtc = DateTimeOffset.UtcNow.AddSeconds(30)
                }
            });

            var client = new PassiveCtSourceClient();
            var requests = new[]
            {
                new PassiveCtSourceClient.SourceRequest
                {
                    SourceName = "crt.sh",
                    Url = $"http://127.0.0.1:{server.Port}/"
                }
            };

            PassiveCtSourceClient.QueryResult result = await client.QueryAsync(
                requests,
                new PassiveCtSourceClient.QueryOptions
                {
                    RetryCount = 0,
                    SourceCooldown = TimeSpan.FromSeconds(30)
                },
                null,
                new InternalLogger(),
                CancellationToken.None);

            Assert.True(result.RetrySuggested);
            Assert.Contains(result.Warnings, static warning => warning.Contains("cooling down", StringComparison.OrdinalIgnoreCase));
            Assert.Equal(0, requestCount);
        }
        finally
        {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task PassiveCtClient_DoesNotCooldownSourceAfterPerHostTimeout()
    {
        var requestSequence = 0;
        var server = new TcpListenerFixture((listener, token) => Task.Run(async () =>
        {
            var handlers = new List<Task>();
            try
            {
                while (!token.IsCancellationRequested)
                {
                    var clientTask = listener.AcceptTcpClientAsync();
                    var completed = await Task.WhenAny(clientTask, Task.Delay(Timeout.Infinite, token));
                    if (completed != clientTask)
                    {
                        break;
                    }

                    handlers.Add(Task.Run(async () =>
                    {
                        using var client = await clientTask;
                        int currentRequest = Interlocked.Increment(ref requestSequence);
                        using NetworkStream stream = client.GetStream();
                        using var reader = new StreamReader(stream);
                        using var writer = new StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                        string? line;
                        do
                        {
                            line = await reader.ReadLineAsync();
                        } while (!string.IsNullOrEmpty(line));

                        if (currentRequest == 1)
                        {
                            await Task.Delay(TimeSpan.FromMilliseconds(250), token);
                            return;
                        }

                        const string payload = @"[{ ""dns_names"": [""api.example.com""] }]";
                        await writer.WriteLineAsync("HTTP/1.1 200 OK");
                        await writer.WriteLineAsync("Content-Type: application/json");
                        await writer.WriteLineAsync($"Content-Length: {payload.Length}");
                        await writer.WriteLineAsync();
                        await writer.WriteAsync(payload);
                    }, token));
                }
            }
            catch (ObjectDisposedException ex) when (token.IsCancellationRequested)
            {
                AssertExpectedListenerCancellation(ex, token);
            }
            catch (SocketException ex) when (token.IsCancellationRequested)
            {
                AssertExpectedListenerCancellation(ex, token);
            }
            finally
            {
                await Task.WhenAll(handlers).ConfigureAwait(false);
            }
        }, token));
        await server.InitializeAsync();

        try
        {
            var client = new PassiveCtSourceClient();
            var requests = new[]
            {
                new PassiveCtSourceClient.SourceRequest
                {
                    SourceName = "crt.sh",
                    Url = $"http://127.0.0.1:{server.Port}/"
                }
            };
            var options = new PassiveCtSourceClient.QueryOptions
            {
                RequestTimeout = TimeSpan.FromMilliseconds(100),
                RetryCount = 0,
                SourceCooldown = TimeSpan.FromSeconds(30)
            };

            PassiveCtSourceClient.QueryResult first = await client.QueryAsync(
                requests,
                options,
                null,
                new InternalLogger(),
                CancellationToken.None);
            await Task.Delay(TimeSpan.FromMilliseconds(300));
            PassiveCtSourceClient.QueryResult second = await client.QueryAsync(
                requests,
                options,
                null,
                new InternalLogger(),
                CancellationToken.None);

            Assert.True(first.RetrySuggested);
            Assert.DoesNotContain(first.Warnings, warning => warning.Contains("Next retry after", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(first.Diagnostics, diagnostic => diagnostic.CooldownUntilUtc.HasValue);
            Assert.DoesNotContain(second.Warnings, warning => warning.Contains("cooling down", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(second.Diagnostics, diagnostic => string.Equals(diagnostic.State, "CoolingDown", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task PassiveCtClient_DoesNotRetryOrCooldownSourceAfterHttp404()
    {
        var requestCount = 0;
        var server = new TcpListenerFixture((listener, token) => Task.Run(async () =>
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    var clientTask = listener.AcceptTcpClientAsync();
                    var completed = await Task.WhenAny(clientTask, Task.Delay(Timeout.Infinite, token));
                    if (completed != clientTask)
                    {
                        break;
                    }

                    using var client = await clientTask;
                    Interlocked.Increment(ref requestCount);
                    using NetworkStream stream = client.GetStream();
                    using var reader = new StreamReader(stream);
                    using var writer = new StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                    string? line;
                    do
                    {
                        line = await reader.ReadLineAsync();
                    } while (!string.IsNullOrEmpty(line));

                    await writer.WriteLineAsync("HTTP/1.1 404 Not Found");
                    await writer.WriteLineAsync("Content-Length: 0");
                    await writer.WriteLineAsync();
                }
            }
            catch (ObjectDisposedException ex) when (token.IsCancellationRequested)
            {
                AssertExpectedListenerCancellation(ex, token);
            }
            catch (SocketException ex) when (token.IsCancellationRequested)
            {
                AssertExpectedListenerCancellation(ex, token);
            }
        }, token));
        await server.InitializeAsync();

        try
        {
            var client = new PassiveCtSourceClient();
            var requests = new[]
            {
                new PassiveCtSourceClient.SourceRequest
                {
                    SourceName = "crt.sh",
                    Url = $"http://127.0.0.1:{server.Port}/"
                }
            };

            PassiveCtSourceClient.QueryResult first = await client.QueryAsync(
                requests,
                new PassiveCtSourceClient.QueryOptions
                {
                    RetryCount = 2,
                    SourceCooldown = TimeSpan.FromSeconds(30)
                },
                null,
                new InternalLogger(),
                CancellationToken.None);
            PassiveCtSourceClient.QueryResult second = await client.QueryAsync(
                requests,
                new PassiveCtSourceClient.QueryOptions
                {
                    RetryCount = 2,
                    SourceCooldown = TimeSpan.FromSeconds(30)
                },
                null,
                new InternalLogger(),
                CancellationToken.None);

            Assert.False(first.RetrySuggested);
            Assert.False(second.RetrySuggested);
            Assert.Contains(first.Warnings, warning => warning.Contains("failed", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(first.Diagnostics, diagnostic => string.Equals(diagnostic.State, "Failed", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(first.Diagnostics, diagnostic => diagnostic.CooldownUntilUtc.HasValue);
            Assert.DoesNotContain(second.Diagnostics, diagnostic => string.Equals(diagnostic.State, "CoolingDown", StringComparison.OrdinalIgnoreCase));
            Assert.Equal(2, requestCount);
        }
        finally
        {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task PassiveCtClient_RespectsConfiguredPerSourceMinimumSpacing()
    {
        var requestOffsets = new List<long>();
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var server = new TcpListenerFixture((listener, token) => Task.Run(async () =>
        {
            var handlers = new List<Task>();
            try
            {
                while (!token.IsCancellationRequested)
                {
                    var clientTask = listener.AcceptTcpClientAsync();
                    var completed = await Task.WhenAny(clientTask, Task.Delay(Timeout.Infinite, token));
                    if (completed != clientTask)
                    {
                        break;
                    }

                    handlers.Add(Task.Run(async () =>
                    {
                        using var client = await clientTask;
                        lock (requestOffsets)
                        {
                            requestOffsets.Add(stopwatch.ElapsedMilliseconds);
                        }

                        using NetworkStream stream = client.GetStream();
                        using var reader = new StreamReader(stream);
                        using var writer = new StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                        string? line;
                        do
                        {
                            line = await reader.ReadLineAsync();
                        } while (!string.IsNullOrEmpty(line));

                        const string payload = @"[{ ""name_value"": ""api.example.com"" }]";
                        await writer.WriteLineAsync("HTTP/1.1 200 OK");
                        await writer.WriteLineAsync("Content-Type: application/json");
                        await writer.WriteLineAsync($"Content-Length: {payload.Length}");
                        await writer.WriteLineAsync();
                        await writer.WriteAsync(payload);
                    }, token));
                }
            }
            catch (ObjectDisposedException ex) when (token.IsCancellationRequested)
            {
                AssertExpectedListenerCancellation(ex, token);
            }
            catch (SocketException ex) when (token.IsCancellationRequested)
            {
                AssertExpectedListenerCancellation(ex, token);
            }
            finally
            {
                await Task.WhenAll(handlers).ConfigureAwait(false);
            }
        }, token));
        await server.InitializeAsync();

        try
        {
            var client = new PassiveCtSourceClient();
            var requests = new[]
            {
                new PassiveCtSourceClient.SourceRequest
                {
                    SourceName = "crt.sh",
                    Url = $"http://127.0.0.1:{server.Port}/"
                }
            };
            var options = new PassiveCtSourceClient.QueryOptions
            {
                RetryCount = 0,
                CrtShMinimumSpacing = TimeSpan.FromMilliseconds(300)
            };

            PassiveCtSourceClient.QueryResult first = await client.QueryAsync(
                requests,
                options,
                null,
                new InternalLogger(),
                CancellationToken.None);
            PassiveCtSourceClient.QueryResult second = await client.QueryAsync(
                requests,
                options,
                null,
                new InternalLogger(),
                CancellationToken.None);

            Assert.False(first.RetrySuggested);
            Assert.False(second.RetrySuggested);
            Assert.Equal(2, requestOffsets.Count);
            Assert.True(requestOffsets[1] - requestOffsets[0] >= 200);
        }
        finally
        {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task AnalyzeAsync_UsesConfiguredPassiveCtSourceSpacingForWildcardDiscovery()
    {
        var requestOffsets = new List<long>();
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var server = new TcpListenerFixture((listener, token) => Task.Run(async () =>
        {
            var handlers = new List<Task>();
            try
            {
                while (!token.IsCancellationRequested)
                {
                    var clientTask = listener.AcceptTcpClientAsync();
                    var completed = await Task.WhenAny(clientTask, Task.Delay(Timeout.Infinite, token));
                    if (completed != clientTask)
                    {
                        break;
                    }

                    handlers.Add(Task.Run(async () =>
                    {
                        using var client = await clientTask;
                        lock (requestOffsets)
                        {
                            requestOffsets.Add(stopwatch.ElapsedMilliseconds);
                        }

                        using NetworkStream stream = client.GetStream();
                        using var reader = new StreamReader(stream);
                        using var writer = new StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                        string? line;
                        do
                        {
                            line = await reader.ReadLineAsync();
                        } while (!string.IsNullOrEmpty(line));

                        const string payload = @"[{ ""name_value"": ""api.example.com"" }]";
                        await writer.WriteLineAsync("HTTP/1.1 200 OK");
                        await writer.WriteLineAsync("Content-Type: application/json");
                        await writer.WriteLineAsync($"Content-Length: {payload.Length}");
                        await writer.WriteLineAsync();
                        await writer.WriteAsync(payload);
                    }, token));
                }
            }
            catch (ObjectDisposedException ex) when (token.IsCancellationRequested)
            {
                AssertExpectedListenerCancellation(ex, token);
            }
            catch (SocketException ex) when (token.IsCancellationRequested)
            {
                AssertExpectedListenerCancellation(ex, token);
            }
            finally
            {
                await Task.WhenAll(handlers).ConfigureAwait(false);
            }
        }, token));
        await server.InitializeAsync();

        try
        {
            var analysis = new SubdomainsAnalysis
            {
                VerifyStillResolves = false,
                UseCertSpotterFallback = false,
                CrtShUrlTemplate = $"http://127.0.0.1:{server.Port}/?q=%25.{{0}}&output=json",
                PassiveCtRetryCount = 0,
                PassiveCtCrtShMinimumSpacing = TimeSpan.FromMilliseconds(300)
            };

            await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);
            await analysis.AnalyzeAsync("example.net", new InternalLogger(), CancellationToken.None);

            Assert.Equal(2, requestOffsets.Count);
            if (RuntimeInformation.FrameworkDescription.StartsWith(".NET Framework", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            Assert.True(requestOffsets[1] - requestOffsets[0] >= 225);
        }
        finally
        {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task PassiveCtClient_StopsUsingSourceAfterConfiguredPerRunBudget()
    {
        var requestCount = 0;
        var server = new TcpListenerFixture((listener, token) => Task.Run(async () =>
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    var clientTask = listener.AcceptTcpClientAsync();
                    var completed = await Task.WhenAny(clientTask, Task.Delay(Timeout.Infinite, token));
                    if (completed != clientTask)
                    {
                        break;
                    }

                    using var client = await clientTask;
                    Interlocked.Increment(ref requestCount);
                    using NetworkStream stream = client.GetStream();
                    using var reader = new StreamReader(stream);
                    using var writer = new StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                    string? line;
                    do
                    {
                        line = await reader.ReadLineAsync();
                    } while (!string.IsNullOrEmpty(line));

                    const string payload = @"[{ ""name_value"": ""api.example.com"" }]";
                    await writer.WriteLineAsync("HTTP/1.1 200 OK");
                    await writer.WriteLineAsync("Content-Type: application/json");
                    await writer.WriteLineAsync($"Content-Length: {payload.Length}");
                    await writer.WriteLineAsync();
                    await writer.WriteAsync(payload);
                }
            }
            catch (ObjectDisposedException ex) when (token.IsCancellationRequested)
            {
                AssertExpectedListenerCancellation(ex, token);
            }
            catch (SocketException ex) when (token.IsCancellationRequested)
            {
                AssertExpectedListenerCancellation(ex, token);
            }
        }, token));
        await server.InitializeAsync();

        try
        {
            var client = new PassiveCtSourceClient();
            var requests = new[]
            {
                new PassiveCtSourceClient.SourceRequest
                {
                    SourceName = "certspotter",
                    Url = $"http://127.0.0.1:{server.Port}/"
                }
            };
            var options = new PassiveCtSourceClient.QueryOptions
            {
                RetryCount = 0,
                SourceCooldown = TimeSpan.FromSeconds(30),
                CertSpotterMaximumRequestsPerRun = 1
            };

            PassiveCtSourceClient.QueryResult first = await client.QueryAsync(
                requests,
                options,
                null,
                new InternalLogger(),
                CancellationToken.None);
            PassiveCtSourceClient.QueryResult second = await client.QueryAsync(
                requests,
                options,
                null,
                new InternalLogger(),
                CancellationToken.None);

            Assert.Single(first.Payloads);
            Assert.Empty(second.Payloads);
            Assert.Contains(second.Warnings, warning => warning.Contains("request budget for this run", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(second.Diagnostics, diagnostic => string.Equals(diagnostic.State, "BudgetExhausted", StringComparison.OrdinalIgnoreCase));
            Assert.Equal(1, requestCount);
        }
        finally
        {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task PassiveCtClient_PreservesDeclaredSourceOrderByDefault()
    {
        var requestedUrls = new List<string>();
        var client = new PassiveCtSourceClient();
        var requests = new[]
        {
            new PassiveCtSourceClient.SourceRequest
            {
                SourceName = "crt.sh",
                Url = "https://crt.sh/?q=%25.example.com&output=json"
            },
            new PassiveCtSourceClient.SourceRequest
            {
                SourceName = "certspotter",
                Url = "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names"
            }
        };

        PassiveCtSourceClient.QueryResult result = await client.QueryAsync(
            requests,
            new PassiveCtSourceClient.QueryOptions
            {
                RetryCount = 0
            },
            (url, _) =>
            {
                requestedUrls.Add(url);
                if (url.Contains("crt.sh", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(@"[{ ""name_value"": ""api.example.com"" }]");
                }

                throw new InvalidOperationException("certspotter should not be queried when the first source succeeds.");
            },
            new InternalLogger(),
            CancellationToken.None);

        Assert.False(result.RetrySuggested);
        Assert.Single(requestedUrls);
        Assert.Contains("crt.sh", requestedUrls[0], StringComparison.OrdinalIgnoreCase);
        var payload = Assert.Single(result.Payloads);
        Assert.Equal("crt.sh", payload.SourceName);
    }

    [Fact]
    public void PassiveCtClient_OrdersHealthySourceAheadOfCooledDownSource()
    {
        PassiveCtSourceClient.ResetSharedStateForTesting();
        try
        {
            CertificateInventoryCapture.RestorePassiveCtSharedCooldownState(
                new[]
                {
                    new PassiveCtDiagnosticEntry
                    {
                        SourceName = "crt.sh",
                        CooldownUntilUtc = DateTimeOffset.UtcNow.AddMinutes(5)
                    }
                });

            var requests = new[]
            {
                new PassiveCtSourceClient.SourceRequest
                {
                    SourceName = "crt.sh",
                    Url = "https://crt.sh/?q=%25.example.com&output=json"
                },
                new PassiveCtSourceClient.SourceRequest
                {
                    SourceName = "certspotter",
                    Url = "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names"
                }
            };

            IReadOnlyList<PassiveCtSourceClient.SourceRequest> ordered =
                PassiveCtSourceClient.OrderRequestsBySourceHealth(requests);

            Assert.Equal("certspotter", ordered[0].SourceName);
            Assert.Equal("crt.sh", ordered[1].SourceName);
        }
        finally
        {
            PassiveCtSourceClient.ResetSharedStateForTesting();
        }
    }

    [Fact]
    public async Task PassiveCtClient_PrefersMostRecentlySuccessfulSourceWhenHealthy()
    {
        PassiveCtSourceClient.ResetSharedStateForTesting();
        try
        {
            var client = new PassiveCtSourceClient();
            await client.QueryAsync(
                new[]
                {
                    new PassiveCtSourceClient.SourceRequest
                    {
                        SourceName = "certspotter",
                        Url = "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names"
                    }
                },
                new PassiveCtSourceClient.QueryOptions
                {
                    RetryCount = 0
                },
                (_, _) => Task.FromResult(@"[{ ""dns_names"": [""api.example.com""] }]"),
                new InternalLogger(),
                CancellationToken.None);

            IReadOnlyList<PassiveCtSourceClient.SourceRequest> ordered =
                PassiveCtSourceClient.OrderRequestsBySourceHealth(
                    new[]
                    {
                        new PassiveCtSourceClient.SourceRequest
                        {
                            SourceName = "crt.sh",
                            Url = "https://crt.sh/?q=%25.example.com&output=json"
                        },
                        new PassiveCtSourceClient.SourceRequest
                        {
                            SourceName = "certspotter",
                            Url = "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names"
                        }
                    });

            Assert.Equal("certspotter", ordered[0].SourceName);
            Assert.Equal("crt.sh", ordered[1].SourceName);
        }
        finally
        {
            PassiveCtSourceClient.ResetSharedStateForTesting();
        }
    }

    [Fact]
    public void PassiveCtClient_LogsSharedCooldownOnlyOncePerCooldownWindow()
    {
        PassiveCtSourceClient.ResetSharedStateForTesting();
        try
        {
            DateTimeOffset firstCooldownUntilUtc = DateTimeOffset.UtcNow.AddMinutes(2);
            DateTimeOffset extendedCooldownUntilUtc = firstCooldownUntilUtc.AddMinutes(1);

            Assert.True(PassiveCtSourceClient.ShouldLogSharedCooldownMessage("crt.sh", firstCooldownUntilUtc));
            Assert.False(PassiveCtSourceClient.ShouldLogSharedCooldownMessage("crt.sh", firstCooldownUntilUtc));
            Assert.True(PassiveCtSourceClient.ShouldLogSharedCooldownMessage("crt.sh", extendedCooldownUntilUtc));
            Assert.True(PassiveCtSourceClient.ShouldLogSharedCooldownMessage("certspotter", firstCooldownUntilUtc));
        }
        finally
        {
            PassiveCtSourceClient.ResetSharedStateForTesting();
        }
    }

    [Fact]
    public async Task NativeCtLogOnlyDiscoversSubdomains()
    {
        using var cert = CreateSelfSigned("api.example.com");
        var entriesJson = BuildCtEntriesResponse(cert, new DateTimeOffset(2026, 1, 10, 0, 0, 0, TimeSpan.Zero));

        var analysis = new SubdomainsAnalysis
        {
            VerifyStillResolves = false,
            EnableNativeCtLogSource = true,
            NativeCtLogOnly = true,
            NativeCtLogListUrl = "https://ct-log-list.example/logs.json",
            NativeCtMaxLogs = 10,
            NativeCtMaxEntriesPerLog = 10,
            NativeCtEntryBatchSize = 10,
            NativeCtInitialBackfillEntriesPerLog = 10,
            NativeCtIncludeRetiredLogs = false,
            QueryOverride = (url, _) =>
            {
                if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""description"": ""Test log"", ""url"": ""ct.test.example/log1/"" } ] } ] }");
                }

                if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(@"{ ""tree_size"": 1 }");
                }

                if (url.Contains("get-entries", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(entriesJson);
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Equal(1, analysis.CertificateObservationCount);
        var api = Assert.Single(analysis.Subdomains, s => s.Name == "api.example.com");
        Assert.False(string.IsNullOrWhiteSpace(api.LatestCertificateSubject));
        Assert.False(string.IsNullOrWhiteSpace(api.LatestCertificateIssuer));
        Assert.False(string.IsNullOrWhiteSpace(api.LatestCertificateSerialNumber));
        Assert.Equal(new DateTimeOffset(2026, 1, 10, 0, 0, 0, TimeSpan.Zero), api.LatestCertificateCtEntryTimestampUtc);
        Assert.True(api.LatestCertificateNotBeforeUtc.HasValue);
        Assert.True(api.LatestCertificateNotAfterUtc.HasValue);
        Assert.True(api.CertificateObservationCount > 0);
        Assert.DoesNotContain(analysis.Subdomains, s => s.Name == "example.com");
        Assert.NotEmpty(analysis.NativeCtLogDiagnostics);
        Assert.Contains(analysis.NativeCtLogDiagnostics, line => line.Contains("ct.test.example/log1/", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task NativeCtFailureFallsBackToCrtShWhenNotNativeOnly()
    {
        const string crtShJson = @"
[
  { ""issuer_name"": ""Issuer A"", ""entry_timestamp"": ""2026-01-01T00:00:00Z"", ""name_value"": ""portal.example.com\nexample.com"" }
]";

        var analysis = new SubdomainsAnalysis
        {
            VerifyStillResolves = false,
            EnableNativeCtLogSource = true,
            NativeCtLogOnly = false,
            NativeCtLogListUrl = "https://ct-log-list.example/logs.json",
            QueryOverride = (url, _) =>
            {
                if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase))
                {
                    throw new HttpRequestException("Native CT source unavailable");
                }

                if (url.Contains("crt.sh", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(crtShJson);
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Contains(analysis.Subdomains, s => s.Name == "portal.example.com");
        Assert.DoesNotContain(analysis.Subdomains, s => s.Name == "example.com");
    }

    private static X509Certificate2 CreateSelfSigned(string cn)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={cn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return CertificateLoaderCompat.LoadCertificate(cert.Export(X509ContentType.Cert));
    }

    private static string BuildCtEntriesResponse(X509Certificate2 certificate, DateTimeOffset timestampUtc)
    {
        var leafInput = BuildCtLeafInput(certificate, timestampUtc.ToUnixTimeMilliseconds());
        return @"{ ""entries"": [ { ""leaf_input"": """ + leafInput + @""", ""extra_data"": """" } ] }";
    }

    private static string BuildCtLeafInput(X509Certificate2 certificate, long timestampMs)
    {
        var certBytes = certificate.Export(X509ContentType.Cert);
        var buffer = new List<byte>(certBytes.Length + 32)
        {
            0x00, // Version
            0x00  // LeafType: timestamped_entry
        };

        AddUInt64(buffer, (ulong)timestampMs);
        AddUInt16(buffer, 0); // EntryType: x509_entry
        AddUInt24(buffer, certBytes.Length);
        buffer.AddRange(certBytes);
        AddUInt16(buffer, 0); // Empty extensions

        return Convert.ToBase64String(buffer.ToArray());
    }

    private static void AddUInt16(ICollection<byte> buffer, int value)
    {
        buffer.Add((byte)((value >> 8) & 0xFF));
        buffer.Add((byte)(value & 0xFF));
    }

    private static void AddUInt24(ICollection<byte> buffer, int value)
    {
        buffer.Add((byte)((value >> 16) & 0xFF));
        buffer.Add((byte)((value >> 8) & 0xFF));
        buffer.Add((byte)(value & 0xFF));
    }

    private static void AddUInt64(ICollection<byte> buffer, ulong value)
    {
        for (var i = 7; i >= 0; i--)
        {
            buffer.Add((byte)((value >> (8 * i)) & 0xFF));
        }
    }
}
