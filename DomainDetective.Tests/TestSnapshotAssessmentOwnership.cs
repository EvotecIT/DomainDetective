namespace DomainDetective.Tests;

public class TestSnapshotAssessmentOwnership {
    [Theory]
    [InlineData(HealthCheckType.HTTP)]
    [InlineData(HealthCheckType.CERT)]
    [InlineData(HealthCheckType.NS)]
    public void FilteredAssessmentsAreIndependentValues(HealthCheckType check) {
        using var source = new DomainHealthCheck();
        var original = Analysis(source, check);
        original.Assessments.Add(new Assessment {
            Severity = AssessmentSeverity.Warning, Message = "Original finding", Code = "Synthetic.Code",
            Category = "Synthetic", Source = "Fixture", Target = "fixture.example",
            Timestamp = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Origin"] = "original" }
        });
        using var filtered = source.FilterAnalyses(new[] { check });
        var copied = Assert.Single(Analysis(filtered, check).Assessments);
        var expected = Assert.Single(original.Assessments);
        Assert.Equal(expected.Timestamp, copied.Timestamp);
        Assert.Equal(expected.Code, copied.Code);
        Assert.Equal(expected.Category, copied.Category);
        Assert.Equal(expected.Source, copied.Source);
        Assert.Equal(expected.Target, copied.Target);
        copied.Severity = AssessmentSeverity.Error;
        copied.Message = "Edited filtered finding";
        copied.Metadata["origin"] = "edited";
        Assert.Equal(AssessmentSeverity.Warning, expected.Severity);
        Assert.Equal("Original finding", expected.Message);
        Assert.Equal("original", expected.Metadata["Origin"]);
        expected.Metadata["Second"] = "source-only";
        Assert.False(copied.Metadata.ContainsKey("second"));
        Assert.Single(copied.Metadata);
    }

    [Theory]
    [InlineData(HealthCheckType.HTTP)]
    [InlineData(HealthCheckType.CERT)]
    [InlineData(HealthCheckType.NS)]
    public void FilteredMapDoesNotConvertAnUnselectedWebsite(HealthCheckType check) {
        using var source = new DomainHealthCheck();
        using var filtered = source.FilterAnalyses(new[] { check });
        var map = filtered.GetAnalysisMap();
        Assert.NotNull(map[check]);
        Assert.Null(map[HealthCheckType.WEBSITE]);
    }

    private static IHasAssessments Analysis(DomainHealthCheck health, HealthCheckType check) => check switch {
        HealthCheckType.HTTP => health.HttpAnalysis,
        HealthCheckType.CERT => health.CertificateAnalysis,
        HealthCheckType.NS => health.NSAnalysis,
        _ => throw new ArgumentOutOfRangeException(nameof(check))
    };
}
