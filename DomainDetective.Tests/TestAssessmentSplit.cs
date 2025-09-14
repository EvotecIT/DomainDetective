using System.Collections.Generic;
using DomainDetective;

namespace DomainDetective.Tests;

public class TestAssessmentSplit
{
    [Fact]
    public void SplitTitlesSeparatesBySeverity()
    {
        var assessments = new List<Assessment>
        {
            new() { Severity = AssessmentSeverity.Info, Message = "info" },
            new() { Severity = AssessmentSeverity.Warning, Message = "warn" },
            new() { Severity = AssessmentSeverity.Error, Message = "err" }
        };

        AssessmentSplit.SplitTitles(assessments, out var positives, out var negatives, out var remediations);

        Assert.Single(positives);
        Assert.Single(negatives);
        Assert.Single(remediations);
        Assert.Contains("info", positives);
        Assert.Contains("warn", negatives);
        Assert.Contains("err", remediations);
    }
}
