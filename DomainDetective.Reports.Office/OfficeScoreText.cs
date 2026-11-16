using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective.Reports.Office;

/// <summary>Score and coverage phrases shared by the Word and Excel assessment exports.</summary>
internal static class OfficeScoreText {
    /// <summary>"84", "84 · 80% of checks judged" or "Not scored" when nothing could be judged.</summary>
    internal static string Score(int? score, double? coverage) {
        if (!score.HasValue) { return "Not scored"; }
        string value = score.Value.ToString(CultureInfo.InvariantCulture);
        return Partial(coverage) ? value + " · " + Percent(coverage!.Value) + " of checks judged" : value;
    }

    /// <summary>"B · 84", with the coverage qualifier when part of the scored evidence was incomplete.</summary>
    internal static string Graded(string grade, int? score, double? coverage) => score.HasValue
        ? grade + " · " + Score(score, coverage) : "Not scored";

    /// <summary>Whether some scored evidence was left out of the score.</summary>
    internal static bool Partial(double? coverage) => coverage.HasValue && coverage.Value < 1;

    internal static string Percent(double value) =>
        ((int)Math.Round(value * 100, MidpointRounding.AwayFromZero)).ToString(CultureInfo.InvariantCulture) + "%";

    /// <summary>Area score across every domain: the same weighted rule as a domain's area score, over all its checks.</summary>
    internal static (int? Score, double? Coverage) Area(IEnumerable<CheckAssessment> checks) {
        List<CheckAssessment> list = checks.ToList();
        return (DomainAssessmentCatalog.CombinedScore(list), DomainAssessmentCatalog.ScoreCoverage(list));
    }

    /// <summary>"and 3 more findings" for warnings and errors beyond the first one, or null.</summary>
    internal static string? MoreFindings(CheckAssessment check) {
        int more = check.ErrorCount + check.WarningCount - 1;
        return more > 0 ? "and " + AssessmentReportWording.Plural(more, "more finding") : null;
    }
}
