using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.Tests;

public class TestCtLogAggregator
{
    public TestCtLogAggregator()
    {
        CtLogAggregator.ResetSharedStateForTests();
    }

    [Fact]
    public async Task AggregatesEntriesFromApis()
    {
        var handler = new SequenceHandler(new[]
        {
            CreateJsonResponse(HttpStatusCode.OK, "[{\"id\":1}]"),
            CreateJsonResponse(HttpStatusCode.OK, "[{\"id\":2}]")
        });

        var aggregator = new CtLogAggregator { HttpHandlerFactory = () => handler };
        aggregator.ApiTemplates.Clear();
        aggregator.ApiTemplates.Add("https://api1/{0}");
        aggregator.ApiTemplates.Add("https://api2/{0}");
        aggregator.MinimumRequestSpacing = TimeSpan.Zero;
        aggregator.RetryDelay = TimeSpan.Zero;

        var entries = await aggregator.QueryAsync("abc");

        Assert.Equal(2, entries.Count);
        Assert.Equal(1, entries[0].GetProperty("id").GetInt32());
        Assert.Equal(2, entries[1].GetProperty("id").GetInt32());
        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task ReusesCacheWithinTtl()
    {
        var handler = new SequenceHandler(new[]
        {
            CreateJsonResponse(HttpStatusCode.OK, "[{\"id\":7}]")
        });

        var aggregator = new CtLogAggregator { HttpHandlerFactory = () => handler };
        aggregator.ApiTemplates.Clear();
        aggregator.ApiTemplates.Add("https://api-cache/{0}");
        aggregator.CacheTtl = TimeSpan.FromMinutes(10);
        aggregator.MinimumRequestSpacing = TimeSpan.Zero;
        aggregator.RetryDelay = TimeSpan.Zero;

        var first = await aggregator.QueryAsync("fingerprint");
        var second = await aggregator.QueryAsync("fingerprint");

        Assert.Single(first);
        Assert.Single(second);
        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task RetriesTransientFailureAndEventuallySucceeds()
    {
        var handler = new SequenceHandler(new[]
        {
            CreateJsonResponse(HttpStatusCode.ServiceUnavailable, string.Empty),
            CreateJsonResponse(HttpStatusCode.OK, "[{\"id\":9}]")
        });

        var aggregator = new CtLogAggregator { HttpHandlerFactory = () => handler };
        aggregator.ApiTemplates.Clear();
        aggregator.ApiTemplates.Add("https://api-retry/{0}");
        aggregator.MaxAttemptsPerRequest = 2;
        aggregator.RetryDelay = TimeSpan.Zero;
        aggregator.MinimumRequestSpacing = TimeSpan.Zero;

        var entries = await aggregator.QueryAsync("retry");

        Assert.Single(entries);
        Assert.Equal(9, entries[0].GetProperty("id").GetInt32());
        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task AppliesRateLimitSpacingBetweenRequests()
    {
        var handler = new SequenceHandler(new[]
        {
            CreateJsonResponse(HttpStatusCode.OK, "[]"),
            CreateJsonResponse(HttpStatusCode.OK, "[]")
        });

        var observedDelays = new List<TimeSpan>();
        var aggregator = new CtLogAggregator { HttpHandlerFactory = () => handler };
        aggregator.ApiTemplates.Clear();
        aggregator.ApiTemplates.Add("https://api-rate1/{0}");
        aggregator.ApiTemplates.Add("https://api-rate2/{0}");
        aggregator.MinimumRequestSpacing = TimeSpan.FromMilliseconds(150);
        aggregator.RetryDelay = TimeSpan.Zero;
        aggregator.DelayOverride = (delay, _) =>
        {
            observedDelays.Add(delay);
            return Task.CompletedTask;
        };

        _ = await aggregator.QueryAsync("rate");

        Assert.True(observedDelays.Count >= 1);
        Assert.Contains(observedDelays, d => d > TimeSpan.Zero);
        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task QueriesCensysWhenEnabledWithCredentials()
    {
        var handler = new SequenceHandler(new[]
        {
            CreateJsonResponse(HttpStatusCode.OK, "{\"result\":{\"fingerprint\":\"abc\"}}")
        });

        var aggregator = new CtLogAggregator { HttpHandlerFactory = () => handler };
        aggregator.ApiTemplates.Clear();
        aggregator.EnableCensysSource = true;
        aggregator.CensysApiId = "id-123";
        aggregator.CensysApiSecret = "secret-456";
        aggregator.CensysApiUrlTemplate = "https://search.censys.io/api/v2/certificates/{0}";
        aggregator.MinimumRequestSpacing = TimeSpan.Zero;
        aggregator.RetryDelay = TimeSpan.Zero;

        var entries = await aggregator.QueryAsync("fingerprintvalue");

        Assert.Single(entries);
        Assert.Equal("abc", entries[0].GetProperty("result").GetProperty("fingerprint").GetString());
        Assert.Equal(1, handler.RequestCount);
        Assert.Single(handler.RequestUrls);
        Assert.Equal("https://search.censys.io/api/v2/certificates/fingerprintvalue", handler.RequestUrls[0]);
        Assert.Single(handler.AuthorizationHeaders);
        var expected = "Basic " + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("id-123:secret-456"));
        Assert.Equal(expected, handler.AuthorizationHeaders[0]);
        Assert.Contains("censys", aggregator.LastQueriedSources);
    }

    [Fact]
    public async Task QueriesShodanWhenEnabledWithApiKey()
    {
        var handler = new SequenceHandler(new[]
        {
            CreateJsonResponse(HttpStatusCode.OK, "{\"matches\":[{\"source\":\"shodan\"}]}")
        });

        var aggregator = new CtLogAggregator { HttpHandlerFactory = () => handler };
        aggregator.ApiTemplates.Clear();
        aggregator.EnableShodanSource = true;
        aggregator.ShodanApiKey = "abc+xyz/123";
        aggregator.ShodanApiUrlTemplate = "https://api.shodan.io/shodan/host/search?key={1}&query=ssl.cert.fingerprint.sha256:{0}";
        aggregator.MinimumRequestSpacing = TimeSpan.Zero;
        aggregator.RetryDelay = TimeSpan.Zero;

        var entries = await aggregator.QueryAsync("fp123");

        Assert.Single(entries);
        Assert.Equal(1, handler.RequestCount);
        Assert.Single(handler.RequestUrls);
        Assert.Contains("key=abc%2Bxyz%2F123", handler.RequestUrls[0], StringComparison.Ordinal);
        Assert.Contains("ssl.cert.fingerprint.sha256:fp123", handler.RequestUrls[0], StringComparison.Ordinal);
        Assert.Contains("shodan", aggregator.LastQueriedSources);
    }

    [Fact]
    public async Task SkipsCensysWhenCredentialsMissing()
    {
        var handler = new SequenceHandler(Array.Empty<HttpResponseMessage>());

        var aggregator = new CtLogAggregator { HttpHandlerFactory = () => handler };
        aggregator.ApiTemplates.Clear();
        aggregator.EnableCensysSource = true;
        aggregator.CensysApiId = "id-only";
        aggregator.CensysApiSecret = null;
        aggregator.MinimumRequestSpacing = TimeSpan.Zero;
        aggregator.RetryDelay = TimeSpan.Zero;

        var entries = await aggregator.QueryAsync("fingerprintvalue");

        Assert.Empty(entries);
        Assert.Equal(0, handler.RequestCount);
        Assert.DoesNotContain("censys", aggregator.LastQueriedSources);
    }

    [Fact]
    public async Task ShodanEmptyMatchesDoesNotCreateCtEvidence()
    {
        var handler = new SequenceHandler(new[]
        {
            CreateJsonResponse(HttpStatusCode.OK, "{\"matches\":[]}")
        });

        var aggregator = new CtLogAggregator { HttpHandlerFactory = () => handler };
        aggregator.ApiTemplates.Clear();
        aggregator.EnableShodanSource = true;
        aggregator.ShodanApiKey = "key";
        aggregator.MinimumRequestSpacing = TimeSpan.Zero;
        aggregator.RetryDelay = TimeSpan.Zero;

        var entries = await aggregator.QueryAsync("fp123");

        Assert.Empty(entries);
        Assert.Equal(1, handler.RequestCount);
        Assert.Contains("shodan", aggregator.LastQueriedSources);
    }

    private static HttpResponseMessage CreateJsonResponse(HttpStatusCode statusCode, string json)
    {
        return new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(json)
        };
    }

    private sealed class SequenceHandler : HttpMessageHandler
    {
        private readonly ConcurrentQueue<HttpResponseMessage> _responses;
        private int _requestCount;
        private readonly ConcurrentQueue<string> _requestUrls = new();
        private readonly ConcurrentQueue<string> _authorizationHeaders = new();

        public SequenceHandler(IEnumerable<HttpResponseMessage> responses)
        {
            _responses = new ConcurrentQueue<HttpResponseMessage>(responses);
        }

        public int RequestCount => Volatile.Read(ref _requestCount);
        public IReadOnlyList<string> RequestUrls => _requestUrls.ToList();
        public IReadOnlyList<string> AuthorizationHeaders => _authorizationHeaders.ToList();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requestCount);
            _requestUrls.Enqueue(request.RequestUri?.ToString() ?? string.Empty);
            if (request.Headers.TryGetValues("Authorization", out var authorization))
            {
                _authorizationHeaders.Enqueue(authorization.FirstOrDefault() ?? string.Empty);
            }

            if (_responses.TryDequeue(out var response))
            {
                return Task.FromResult(response);
            }

            return Task.FromResult(CreateJsonResponse(HttpStatusCode.OK, "[]"));
        }
    }
}
