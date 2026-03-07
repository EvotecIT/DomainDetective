using System;
using System.Linq;

namespace DomainDetective.Reports;

public static partial class SectionProjectors
{
    public sealed class SimpleRecommendation
    {
        public string Code { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string How { get; set; } = string.Empty;

        public SimpleRecommendation()
        {
        }

        public SimpleRecommendation(string code, string title, string how)
        {
            Code = code;
            Title = title;
            How = how;
        }
    }

    public sealed class DesiredStateSection
    {
        public string Status { get; set; } = "-";
        public string Mode { get; set; } = "-";
        public bool Conforms { get; set; }
        public int DesiredWarningCount { get; set; }
        public int DesiredErrorCount { get; set; }
        public int BestPracticeWarningCount { get; set; }
        public int BestPracticeErrorCount { get; set; }
        public bool IsBaselineOnly { get; set; }
        public System.Collections.Generic.List<(string Key, string Value)> Summary { get; } = new();
        public System.Collections.Generic.List<SimpleFinding> DesiredFindings { get; } = new();
        public System.Collections.Generic.List<string> DesiredPositives { get; } = new();
        public System.Collections.Generic.List<SimpleRecommendation> DesiredRecommendations { get; } = new();
        public System.Collections.Generic.List<SimpleFinding> BestPracticeFindings { get; } = new();
        public System.Collections.Generic.List<string> BestPracticePositives { get; } = new();
        public System.Collections.Generic.List<SimpleRecommendation> BestPracticeRecommendations { get; } = new();
        public System.Collections.Generic.List<string> References { get; } = new();
    }

    public static DesiredStateSection? BuildDesiredState(DomainDetective.Views.DesiredStateInfo ds)
    {
        if (ds == null)
        {
            return null;
        }

        var sec = new DesiredStateSection
        {
            Mode = ds.Mode.ToString(),
            Conforms = ds.Conforms,
            DesiredWarningCount = ds.WarningCount,
            DesiredErrorCount = ds.ErrorCount,
            BestPracticeWarningCount = ds.BestPracticeWarningCount,
            BestPracticeErrorCount = ds.BestPracticeErrorCount,
            IsBaselineOnly = ds.Mode == DomainDetective.DesiredState.DesiredStateMode.BaselineOnly
        };

        sec.Status = sec.DesiredErrorCount > 0
            ? "Error"
            : (sec.DesiredWarningCount > 0 ? "Warning" : "OK");

        sec.Summary.Add(("Mode", sec.Mode));
        sec.Summary.Add(("Conforms", sec.Conforms ? "Yes" : "No"));
        sec.Summary.Add(("Desired Warnings", sec.DesiredWarningCount.ToString()));
        sec.Summary.Add(("Desired Errors", sec.DesiredErrorCount.ToString()));
        sec.Summary.Add(("Best-Practice Warnings", sec.BestPracticeWarningCount.ToString()));
        sec.Summary.Add(("Best-Practice Errors", sec.BestPracticeErrorCount.ToString()));

        foreach (var a in (ds.DesiredAssessments ?? Array.Empty<DomainDetective.Assessment>())
            .Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info))
        {
            sec.DesiredFindings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        }

        foreach (var p in ds.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            var title = p?.Title ?? p?.Code;
            if (!string.IsNullOrWhiteSpace(title))
            {
                sec.DesiredPositives.Add(title!);
            }
        }

        foreach (var r in ds.Recommendations ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            if (r == null)
            {
                continue;
            }

            var code = r.Code ?? string.Empty;
            var title = r.Title ?? string.Empty;
            var how = r.How ?? string.Empty;
            if (string.IsNullOrWhiteSpace(code) && string.IsNullOrWhiteSpace(title) && string.IsNullOrWhiteSpace(how))
            {
                continue;
            }

            sec.DesiredRecommendations.Add(new SimpleRecommendation(code, title, how));
        }

        foreach (var a in (ds.BestPracticeAssessments ?? Array.Empty<DomainDetective.Assessment>())
            .Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info))
        {
            sec.BestPracticeFindings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        }

        foreach (var p in ds.BestPracticePositives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            var title = p?.Title ?? p?.Code;
            if (!string.IsNullOrWhiteSpace(title))
            {
                sec.BestPracticePositives.Add(title!);
            }
        }

        foreach (var r in ds.BestPracticeRecommendations ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            if (r == null)
            {
                continue;
            }

            var code = r.Code ?? string.Empty;
            var title = r.Title ?? string.Empty;
            var how = r.How ?? string.Empty;
            if (string.IsNullOrWhiteSpace(code) && string.IsNullOrWhiteSpace(title) && string.IsNullOrWhiteSpace(how))
            {
                continue;
            }

            sec.BestPracticeRecommendations.Add(new SimpleRecommendation(code, title, how));
        }

        foreach (var reference in ds.References ?? Array.Empty<string>())
        {
            if (!string.IsNullOrWhiteSpace(reference))
            {
                sec.References.Add(reference);
            }
        }

        return sec;
    }
}
