using System;
using System.Linq;

namespace DomainDetective.Reports;

public static class ProviderHintsBuilder
{
    public sealed class Hints
    {
        public int ConfidencePercent { get; }
        public bool SingleMxOk { get; }
        public int MinDkimSelectorsToPass { get; }
        public int RecommendedMinMxRecords { get; }
        public Hints(int confidencePercent, bool singleMxOk, int minDkimSelectorsToPass, int recommendedMinMxRecords)
        { ConfidencePercent = confidencePercent; SingleMxOk = singleMxOk; MinDkimSelectorsToPass = minDkimSelectorsToPass; RecommendedMinMxRecords = recommendedMinMxRecords; }
    }

    public static Hints Build(DomainDetective.Views.MxInfo? mx, string? primaryDisplayName)
    {
        int confidence = 0;
        try { confidence = (int)Math.Round(Math.Max(0.0, Math.Min(1.0, (mx?.ProviderPrimaryScore ?? 0.0) / 1.2)) * 100.0); } catch { confidence = 0; }

        bool singleMxOk = false;
        int minDkim = 0;
        int recMx = 0;
        try
        {
            if (!string.IsNullOrWhiteSpace(primaryDisplayName))
            {
                var meta = DomainDetective.Providers.Email.ProviderRegistry.All.FirstOrDefault(p => string.Equals(p?.DisplayName, primaryDisplayName, StringComparison.OrdinalIgnoreCase));
                if (meta != null)
                {
                    singleMxOk = meta.SingleMxOk;
                    minDkim = meta.MinimumDkimSelectorsToPass;
                    recMx = meta.RecommendedMinMxRecords;
                }
            }
        }
        catch { }

        return new Hints(confidence, singleMxOk, minDkim, recMx);
    }
}
