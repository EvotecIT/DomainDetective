using System.Collections.Concurrent;
using System.Collections.Generic;
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

        public SequenceHandler(IEnumerable<HttpResponseMessage> responses)
        {
            _responses = new ConcurrentQueue<HttpResponseMessage>(responses);
        }

        public int RequestCount => Volatile.Read(ref _requestCount);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requestCount);
            if (_responses.TryDequeue(out var response))
            {
                return Task.FromResult(response);
            }

            return Task.FromResult(CreateJsonResponse(HttpStatusCode.OK, "[]"));
        }
    }
}
