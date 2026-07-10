using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static DaneRecordInfo Convert(DANEAnalysis analysis)
    {
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var narrative = DomainDetective.Narratives.DaneNarrative.Build(analysis, analysis.Assessments);
        var records = analysis.AnalysisResults?.ToList() ?? new List<DANERecordAnalysis>();
        var validRecordCount = records.Count(static record => record.ValidDANERecord);
        var recommendedRecordCount = records.Count(static record => record.IsValidChoiceForSmtp || record.IsValidChoiceForHttps);
        return new DaneRecordInfo
        {
            Check = HealthCheckType.DANE,
            Area = AreaForKind(HealthCheckType.DANE),
            Subject = analysis.Subject ?? string.Empty,
            NumberOfRecords = analysis.NumberOfRecords,
            HasDuplicateRecords = analysis.HasDuplicateRecords,
            HasInvalidRecords = analysis.HasInvalidRecords,
            QueriedNames = analysis.QueriedNames.ToList(),
            QueriedPorts = analysis.QueriedPorts.ToList(),
            QueriedServiceTypes = analysis.QueriedServiceTypes.Select(static serviceType => serviceType.ToString()).ToList(),
            Records = records,
            ValidRecordCount = validRecordCount,
            RecommendedRecordCount = recommendedRecordCount,
            AssociationValidationPerformed = analysis.AssociationValidationPerformed,
            AllCertificateAssociationsMatch = analysis.AllCertificateAssociationsMatch,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"{analysis.NumberOfRecords} records; invalid {(analysis.HasInvalidRecords ? "yes" : "no")}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(analysis.RfcReferences, recs),
            Narrative = narrative,
            Highlights = narrative.Highlights?.ToList() ?? new List<string>(),
            Details = narrative.Details?.ToList() ?? new List<string>(),
            Raw = analysis
        };
    }
}

/// <summary>
/// View model summarizing DANE (TLSA) record analysis.
/// </summary>
public class DaneRecordInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string Subject { get; set; } = string.Empty;
    /// <summary>Gets or sets the number of records value.</summary>
    public int NumberOfRecords { get; set; }
    /// <summary>Gets or sets the has duplicate records value.</summary>
    public bool HasDuplicateRecords { get; set; }
    /// <summary>Gets or sets the has invalid records value.</summary>
    public bool HasInvalidRecords { get; set; }
    /// <summary>Gets or sets the queried names value.</summary>
    public IReadOnlyList<string> QueriedNames { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the queried ports value.</summary>
    public IReadOnlyList<int> QueriedPorts { get; set; } = System.Array.Empty<int>();
    /// <summary>Gets or sets the queried service types value.</summary>
    public IReadOnlyList<string> QueriedServiceTypes { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the records value.</summary>
    public IReadOnlyList<DANERecordAnalysis> Records { get; set; } = System.Array.Empty<DANERecordAnalysis>();
    /// <summary>Gets or sets the valid record count value.</summary>
    public int ValidRecordCount { get; set; }
    /// <summary>Gets or sets the recommended record count value.</summary>
    public int RecommendedRecordCount { get; set; }
    /// <summary>True when live certificate association matching was attempted.</summary>
    public bool AssociationValidationPerformed { get; set; }
    /// <summary>True when all syntactically valid TLSA records matched live certificate evidence.</summary>
    public bool AllCertificateAssociationsMatch { get; set; }
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the narrative value.</summary>
    public DomainDetective.Narratives.DaneNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.DaneNarrative.Sections();
    /// <summary>Gets or sets the highlights value.</summary>
    public IReadOnlyList<string> Highlights { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the details value.</summary>
    public IReadOnlyList<string> Details { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the raw value.</summary>
    public DANEAnalysis Raw { get; set; } = new DANEAnalysis();
}
