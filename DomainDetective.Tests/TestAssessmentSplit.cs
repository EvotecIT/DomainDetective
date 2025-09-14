using System.Collections.Generic;

namespace DomainDetective.Tests;

public class TestAssessmentSplit
{
    [Fact]
    public void SplitTitlesSeparatesBySeverity()
    {
        var assessments = new List<Assessment>
        {
            new() { Severity = AssessmentSeverity.Info, Message = "Info", Code = "I1" },
            new() { Severity = AssessmentSeverity.Warning, Message = "Warn", Code = "W1" },
            new() { Severity = AssessmentSeverity.Error, Message = "Err", Code = "E1" }
        };

        var (positives, negatives, remediations) = AssessmentSplit.SplitTitles(assessments);

        Assert.Single(positives);
        Assert.Contains("Info", positives);

        Assert.Single(negatives);
        Assert.Contains("Warn", negatives);

        Assert.Single(remediations);
        Assert.Contains("Err", remediations);
    }
}
