using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

internal sealed class PassiveCtSourceClient
{
    private sealed class SourceState
    {
        public DateTimeOffset CooldownUntilUtc { get; set; }
        public int ConsecutiveFailures { get; set; }
    }

    internal sealed class SourceRequest
    {
        public required string SourceName { get; init; }
        public required string Url { get; init; }
    }

    internal sealed class SourcePayload
    {
        public required string SourceName { get; init; }
        public required string Url { get; init; }
        public required string Payload { get; init; }
    }

    internal sealed class QueryResult
    {
        public List<SourcePayload> Payloads { get; } = new();
        public List<string> Warnings { get; } = new();
        public bool RetrySuggested { get; set; }
    }

    internal sealed class QueryOptions
    {
        public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(15);
        public int RetryCount { get; init; } = 2;
        public TimeSpan RetryBaseDelay { get; init; } = TimeSpan.FromMilliseconds(750);
        public TimeSpan RetryMaxDelay { get; init; } = TimeSpan.FromSeconds(15);
        public TimeSpan SourceCooldown { get; init; } = TimeSpan.FromSeconds(60);
        public bool QueryAllSources { get; init; }
        public Func<string, string?>? PayloadValidator { get; init; }
    }

    private sealed class FetchOutcome
    {
        public string? Payload { get; init; }
        public string? Failure { get; init; }
        public bool RetrySuggested { get; init; }
        public TimeSpan? RetryAfter { get; init; }
    }

    private static readonly ConcurrentDictionary<string, SourceState> SharedSourceStates = new(StringComparer.OrdinalIgnoreCase);
    private static int _rotationCursor = -1;

    public async Task<QueryResult> QueryAsync(
        IReadOnlyList<SourceRequest> requests,
        QueryOptions options,
        Func<string, CancellationToken, Task<string>>? queryOverride,
        InternalLogger? logger,
        CancellationToken cancellationToken)
    {
        var result = new QueryResult();
        if (requests == null || requests.Count == 0)
        {
            return result;
        }

        QueryOptions effectiveOptions = NormalizeOptions(options);
        IReadOnlyList<SourceRequest> rotated = RotateRequests(requests);
        bool useSharedSourceState = queryOverride == null;
        foreach (SourceRequest request in rotated)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (useSharedSourceState &&
                TryGetCooldown(request.SourceName, out DateTimeOffset cooldownUntilUtc))
            {
                result.RetrySuggested = true;
                string cooldownMessage =
                    "Passive CT source '" +
                    request.SourceName +
                    "' is cooling down until " +
                    cooldownUntilUtc.ToString("u") +
                    "; check later or let the next run retry.";
                result.Warnings.Add(cooldownMessage);
                logger?.WriteVerbose("{0}", cooldownMessage);
                continue;
            }

            FetchOutcome outcome = await FetchSourceAsync(
                request,
                effectiveOptions,
                queryOverride,
                cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(outcome.Payload))
            {
                string? payloadValidationFailure = ValidatePayload(outcome.Payload!, effectiveOptions.PayloadValidator);
                if (!string.IsNullOrWhiteSpace(payloadValidationFailure))
                {
                    string warning =
                        "Passive CT source '" +
                        request.SourceName +
                        "' returned an invalid payload: " +
                        payloadValidationFailure;
                    result.Warnings.Add(warning);
                    logger?.WriteVerbose("{0}", warning);
                    continue;
                }

                if (useSharedSourceState)
                {
                    ResetState(request.SourceName);
                }

                result.Payloads.Add(new SourcePayload
                {
                    SourceName = request.SourceName,
                    Url = request.Url,
                    Payload = outcome.Payload!
                });
                if (!effectiveOptions.QueryAllSources)
                {
                    break;
                }

                continue;
            }

            if (outcome.RetrySuggested)
            {
                TimeSpan cooldown = outcome.RetryAfter.GetValueOrDefault(effectiveOptions.SourceCooldown);
                if (cooldown <= TimeSpan.Zero)
                {
                    cooldown = effectiveOptions.SourceCooldown;
                }

                result.RetrySuggested = true;
                string warning =
                    "Passive CT source '" +
                    request.SourceName +
                    "' is temporarily unavailable";
                if (!string.IsNullOrWhiteSpace(outcome.Failure))
                {
                    warning += ": " + outcome.Failure;
                }

                if (useSharedSourceState)
                {
                    DateTimeOffset retryUtc = MarkTransientFailure(request.SourceName, cooldown);
                    warning += ". Next retry after " + retryUtc.ToString("u") + ".";
                }
                else
                {
                    warning += ".";
                }

                result.Warnings.Add(warning);
                logger?.WriteVerbose("{0}", warning);
            }
            else if (!string.IsNullOrWhiteSpace(outcome.Failure))
            {
                string warning = "Passive CT source '" + request.SourceName + "' failed: " + outcome.Failure;
                result.Warnings.Add(warning);
                logger?.WriteVerbose("{0}", warning);
            }
        }

        if (result.Payloads.Count == 0 && result.RetrySuggested)
        {
            result.Warnings.Add("Passive CT sources were temporarily unavailable or rate-limited; check later or let the next monitoring cycle retry.");
        }

        return result;
    }

    private static QueryOptions NormalizeOptions(QueryOptions? options)
    {
        TimeSpan requestTimeout = options?.RequestTimeout ?? TimeSpan.FromSeconds(15);
        if (requestTimeout <= TimeSpan.Zero)
        {
            requestTimeout = TimeSpan.FromSeconds(15);
        }

        TimeSpan retryBaseDelay = options?.RetryBaseDelay ?? TimeSpan.FromMilliseconds(750);
        if (retryBaseDelay < TimeSpan.Zero)
        {
            retryBaseDelay = TimeSpan.Zero;
        }

        TimeSpan retryMaxDelay = options?.RetryMaxDelay ?? TimeSpan.FromSeconds(15);
        if (retryMaxDelay <= TimeSpan.Zero)
        {
            retryMaxDelay = TimeSpan.FromSeconds(15);
        }

        if (retryMaxDelay < retryBaseDelay)
        {
            retryMaxDelay = retryBaseDelay;
        }

        TimeSpan sourceCooldown = options?.SourceCooldown ?? TimeSpan.FromSeconds(60);
        if (sourceCooldown < TimeSpan.Zero)
        {
            sourceCooldown = TimeSpan.Zero;
        }

        return new QueryOptions
        {
            RequestTimeout = requestTimeout,
            RetryCount = Math.Max(0, options?.RetryCount ?? 2),
            RetryBaseDelay = retryBaseDelay,
            RetryMaxDelay = retryMaxDelay,
            SourceCooldown = sourceCooldown,
            QueryAllSources = options?.QueryAllSources ?? false,
            PayloadValidator = options?.PayloadValidator
        };
    }

    private static string? ValidatePayload(string payload, Func<string, string?>? payloadValidator)
    {
        if (payloadValidator == null)
        {
            return null;
        }

        return payloadValidator(payload);
    }

    private static IReadOnlyList<SourceRequest> RotateRequests(IReadOnlyList<SourceRequest> requests)
    {
        if (requests.Count <= 1)
        {
            return requests;
        }

        int start = Math.Abs(Interlocked.Increment(ref _rotationCursor));
        if (start >= requests.Count)
        {
            start %= requests.Count;
        }

        var rotated = new List<SourceRequest>(requests.Count);
        for (int index = 0; index < requests.Count; index++)
        {
            rotated.Add(requests[(start + index) % requests.Count]);
        }

        return rotated;
    }

    private static bool TryGetCooldown(string sourceName, out DateTimeOffset cooldownUntilUtc)
    {
        cooldownUntilUtc = DateTimeOffset.MinValue;
        if (!SharedSourceStates.TryGetValue(sourceName, out SourceState? state))
        {
            return false;
        }

        lock (state)
        {
            if (state.CooldownUntilUtc <= DateTimeOffset.UtcNow)
            {
                state.CooldownUntilUtc = DateTimeOffset.MinValue;
                return false;
            }

            cooldownUntilUtc = state.CooldownUntilUtc;
            return true;
        }
    }

    private static DateTimeOffset MarkTransientFailure(string sourceName, TimeSpan cooldown)
    {
        SourceState state = SharedSourceStates.GetOrAdd(sourceName, static _ => new SourceState());
        lock (state)
        {
            state.ConsecutiveFailures++;
            DateTimeOffset nowUtc = DateTimeOffset.UtcNow;
            DateTimeOffset requestedUntilUtc = cooldown <= TimeSpan.Zero ? nowUtc : nowUtc + cooldown;
            if (requestedUntilUtc > state.CooldownUntilUtc)
            {
                state.CooldownUntilUtc = requestedUntilUtc;
            }

            return state.CooldownUntilUtc;
        }
    }

    private static void ResetState(string sourceName)
    {
        if (!SharedSourceStates.TryGetValue(sourceName, out SourceState? state))
        {
            return;
        }

        lock (state)
        {
            state.ConsecutiveFailures = 0;
            state.CooldownUntilUtc = DateTimeOffset.MinValue;
        }
    }

    private static async Task<FetchOutcome> FetchSourceAsync(
        SourceRequest request,
        QueryOptions options,
        Func<string, CancellationToken, Task<string>>? queryOverride,
        CancellationToken cancellationToken)
    {
        int retryCount = Math.Max(0, options.RetryCount);
        for (int attempt = 0; attempt <= retryCount; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                string payload = await FetchPayloadAsync(
                    request.Url,
                    options.RequestTimeout,
                    queryOverride,
                    cancellationToken).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(payload))
                {
                    return new FetchOutcome
                    {
                        Payload = payload
                    };
                }

                return new FetchOutcome
                {
                    Failure = "empty response payload."
                };
            }
            catch (Exception ex) when (IsTransientException(ex, cancellationToken, out TimeSpan? retryAfter))
            {
                if (attempt >= retryCount)
                {
                    return new FetchOutcome
                    {
                        Failure = ex.Message,
                        RetrySuggested = true,
                        RetryAfter = retryAfter
                    };
                }

                TimeSpan delay = ComputeRetryDelay(attempt, options.RetryBaseDelay, options.RetryMaxDelay, retryAfter);
                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                return new FetchOutcome
                {
                    Failure = ex.Message
                };
            }
        }

        return new FetchOutcome
        {
            Failure = "unknown passive CT failure.",
            RetrySuggested = true
        };
    }

    private static async Task<string> FetchPayloadAsync(
        string url,
        TimeSpan requestTimeout,
        Func<string, CancellationToken, Task<string>>? queryOverride,
        CancellationToken cancellationToken)
    {
        if (queryOverride != null)
        {
            using var overrideCts = CreateLinkedTimeoutCts(requestTimeout, cancellationToken);
            return await queryOverride(url, overrideCts.Token).ConfigureAwait(false);
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        using var requestCts = CreateLinkedTimeoutCts(requestTimeout, cancellationToken);
        using HttpResponseMessage response = await SharedHttpClient.Instance
            .SendAsync(request, requestCts.Token)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            string message = "HTTP " + (int)response.StatusCode + " " + response.ReasonPhrase;
            if (ShouldRetryStatusCode(response.StatusCode))
            {
                TimeSpan retryAfter = ComputeRetryAfterDelay(response);
                throw new HttpRequestException(
                    retryAfter > TimeSpan.Zero
                        ? message + " (Retry-After " + (int)Math.Ceiling(retryAfter.TotalSeconds) + "s)"
                        : message);
            }

            throw new InvalidOperationException(message);
        }

        return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    }

    private static CancellationTokenSource CreateLinkedTimeoutCts(TimeSpan timeout, CancellationToken cancellationToken)
    {
        CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (timeout > TimeSpan.Zero && timeout != Timeout.InfiniteTimeSpan)
        {
            linked.CancelAfter(timeout);
        }

        return linked;
    }

    private static bool IsTransientException(Exception ex, CancellationToken cancellationToken, out TimeSpan? retryAfter)
    {
        retryAfter = null;
        if (ex is TaskCanceledException)
        {
            return !cancellationToken.IsCancellationRequested;
        }

        if (ex is TimeoutException)
        {
            return true;
        }

        if (ex is HttpRequestException httpEx)
        {
            int? statusCode = TryGetHttpStatusCode(httpEx);
            if (!statusCode.HasValue)
            {
                return true;
            }

            if (ShouldRetryStatusCode((HttpStatusCode)statusCode.Value))
            {
                retryAfter = TryGetRetryAfterFromMessage(httpEx.Message);
                return true;
            }

            return false;
        }

        return false;
    }

    private static bool ShouldRetryStatusCode(HttpStatusCode statusCode)
    {
        int code = (int)statusCode;
        return statusCode == HttpStatusCode.RequestTimeout ||
               statusCode == HttpStatusCode.BadGateway ||
               statusCode == HttpStatusCode.ServiceUnavailable ||
               statusCode == HttpStatusCode.GatewayTimeout ||
               code == 425 ||
               code == 429;
    }

    private static TimeSpan ComputeRetryDelay(int attempt, TimeSpan baseDelay, TimeSpan maxDelay, TimeSpan? retryAfter)
    {
        if (retryAfter.HasValue && retryAfter.Value > TimeSpan.Zero)
        {
            return retryAfter.Value > maxDelay ? maxDelay : retryAfter.Value;
        }

        if (baseDelay <= TimeSpan.Zero)
        {
            return TimeSpan.Zero;
        }

        double multiplier = Math.Pow(2d, attempt);
        double delayMs = baseDelay.TotalMilliseconds * multiplier;
        if (delayMs <= 0d)
        {
            return TimeSpan.Zero;
        }

        if (delayMs > maxDelay.TotalMilliseconds)
        {
            delayMs = maxDelay.TotalMilliseconds;
        }

        return TimeSpan.FromMilliseconds(delayMs);
    }

    private static TimeSpan ComputeRetryAfterDelay(HttpResponseMessage response)
    {
        if (response.Headers.RetryAfter == null)
        {
            return TimeSpan.Zero;
        }

        if (response.Headers.RetryAfter.Delta.HasValue &&
            response.Headers.RetryAfter.Delta.Value > TimeSpan.Zero)
        {
            return response.Headers.RetryAfter.Delta.Value;
        }

        if (response.Headers.RetryAfter.Date.HasValue)
        {
            TimeSpan delta = response.Headers.RetryAfter.Date.Value - DateTimeOffset.UtcNow;
            if (delta > TimeSpan.Zero)
            {
                return delta;
            }
        }

        return TimeSpan.Zero;
    }

    private static TimeSpan? TryGetRetryAfterFromMessage(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return null;
        }

        string messageText = message!;
        const string needle = "Retry-After";
        int index = messageText.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return null;
        }

        string tail = messageText.Substring(index + needle.Length).Trim();
        if (tail.StartsWith(":", StringComparison.Ordinal))
        {
            tail = tail.Substring(1).Trim();
        }

        int secondsIndex = tail.IndexOf('s');
        if (secondsIndex > 0 &&
            int.TryParse(tail.Substring(0, secondsIndex).Trim(), out int seconds) &&
            seconds > 0)
        {
            return TimeSpan.FromSeconds(seconds);
        }

        return null;
    }

    private static int? TryGetHttpStatusCode(HttpRequestException exception)
    {
        if (exception == null)
        {
            return null;
        }

#if NET5_0_OR_GREATER
        if (exception.StatusCode.HasValue)
        {
            return (int)exception.StatusCode.Value;
        }
#endif

        string? message = exception.Message;
        if (!string.IsNullOrWhiteSpace(message))
        {
            string messageText = message!;
            const string needle = "HTTP ";
            int index = messageText.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                string tail = messageText.Substring(index + needle.Length);
                int end = tail.IndexOf(' ');
                string codeText = end > 0 ? tail.Substring(0, end) : tail;
                if (int.TryParse(codeText.Trim(), out int code))
                {
                    return code;
                }
            }
        }

        var property = exception.GetType().GetProperty("StatusCode");
        if (property == null)
        {
            return null;
        }

        object? raw = property.GetValue(exception, null);
        if (raw == null)
        {
            return null;
        }

        try
        {
            return Convert.ToInt32(raw);
        }
        catch
        {
            return null;
        }
    }
}
