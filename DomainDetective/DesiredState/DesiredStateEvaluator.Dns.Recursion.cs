using System.Collections.Generic;

namespace DomainDetective.DesiredState;

public static partial class DesiredStateEvaluator {
    private static void EvaluateOpenResolver(string domain, OpenResolverAnalysis analysis, DesiredStateOpenResolverPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;
        if (analysis == null) return;

        var results = analysis.ServerResults ?? new Dictionary<string, bool>();

        if (desired.RequireAtLeastOneResult == true && results.Count == 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.OpenResolverNoResults,
                Message = "Desired state expected open resolver results, but no results were produced."
            });
            return;
        }

        if (results.Count == 0) {
            return;
        }

        if (desired.DisallowOpenResolver != true) {
            return;
        }

        foreach (var kvp in results) {
            if (!kvp.Value) continue;
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.OpenResolverNotAllowed,
                Message = $"Desired state disallows open DNS recursion, but '{kvp.Key}' allowed recursion."
            });
        }
    }
}

