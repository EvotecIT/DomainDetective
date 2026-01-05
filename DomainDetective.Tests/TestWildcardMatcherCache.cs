using DomainDetective.DesiredState;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestWildcardMatcherCache {
    [Fact]
    public void Cache_Evicts_When_Over_Limit() {
        WildcardMatcher.ClearCacheForTesting();

        var input = "mail.example.com";
        var total = WildcardMatcher.CacheLimitValue + 25;
        for (var i = 0; i < total; i++) {
            var pattern = $"*.example{i}.com";
            _ = WildcardMatcher.IsMatch(input, pattern);
        }

        Assert.True(WildcardMatcher.CacheCount <= WildcardMatcher.CacheLimitValue);
    }
}
