using System;
using DomainDetective;
using DomainDetective.Recommendations;

namespace DomainDetective.Tests;

public class TestProviderRecommendations
{
    [Fact]
    public void MtaSts_TlsRpt_Provider_Advice_Mapped()
    {
        // RecommendationCatalog auto-registers providers statically. Ensure our new codes are available.
        Assert.True(RecommendationCatalog.TryGet(MtaStsCodes.ProviderRecommended, out _));
        Assert.True(RecommendationCatalog.TryGet(TlsRptCodes.ProviderRecommended, out _));
        Assert.True(RecommendationCatalog.TryGet(DkimCodes.SelectorsMinimumMet, out _));
        Assert.True(RecommendationCatalog.TryGet(DkimCodes.SelectorsMinimumNotMet, out _));
        Assert.True(RecommendationCatalog.TryGet(SpfCodes.ProviderIncludeMissing, out _));
        Assert.True(RecommendationCatalog.TryGet(SpfCodes.ProviderIncludePresent, out _));
    }
}
