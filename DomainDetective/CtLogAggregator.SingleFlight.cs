using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public sealed partial class CtLogAggregator {
    private sealed record FetchResult(bool Complete, IReadOnlyList<JsonElement> Entries);
    private static readonly Helpers.SharedAsyncOperations SharedFetches = new();

    // Handler, credentials and retry policy identify compatible in-flight work.
    // Completed public-response cache identity retains the existing source policy.
    private Task<FetchResult> FetchSharedAsync(CtDiscoveryRequest request, CancellationToken caller) {
        object key = (request.CacheKey, request.ResponseParser, HttpHandlerFactory,
            MaxAttemptsPerRequest, RetryDelay, DelayOverride, CredentialIdentity(
                request.Headers != null && request.Headers.TryGetValue("Authorization", out var authorization)
                    ? authorization : request.SourceName == "shodan" ? ShodanApiKey ?? string.Empty : string.Empty));
        return SharedFetches.RunAsync(key, async token => {
            if (TryGetCachedEntries(request.CacheKey, out var cached)) { return new FetchResult(true, cached); }
            var client = CreateClient(out var dispose);
            try {
                var result = await FetchEntriesWithRetryAsync(client, request, token).ConfigureAwait(false);
                if (result.Complete) { CacheEntries(request.CacheKey, result.Entries); }
                return result;
            } finally { if (dispose) { client.Dispose(); } }
        }, caller);
    }

    private static FetchResult ParseFetchResult(string json, CtResponseParserKind parser) {
        try {
            using var parsed = JsonDocument.Parse(json);
            bool complete = parsed.RootElement.ValueKind == JsonValueKind.Array ||
                parsed.RootElement.ValueKind == JsonValueKind.Object &&
                (parser != CtResponseParserKind.ShodanMatches ||
                 parsed.RootElement.TryGetProperty("matches", out var matches) && matches.ValueKind == JsonValueKind.Array);
            return new FetchResult(complete, ParseEntries(json, parser));
        } catch (JsonException) { return new FetchResult(false, Array.Empty<JsonElement>()); }
    }

    private static string CredentialIdentity(string credential) {
        using var hash = SHA256.Create();
        return BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(credential))).Replace("-", string.Empty);
    }
}
