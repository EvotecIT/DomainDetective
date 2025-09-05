using System;
using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static ContactInfo Convert(ContactInfoAnalysis analysis)
    {
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Summarize(analysis.Assessments, out var warn, out var err, out var status);
        return new ContactInfo
        {
            Check = HealthCheckType.CONTACT,
            Area = AreaForKind(HealthCheckType.CONTACT),
            Subject = analysis.Subject,
            RecordExists = analysis.RecordExists,
            ContactRecord = analysis.ContactRecord,
            Fields = analysis.Fields,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = err,
            Summary = analysis.RecordExists ? "present" : "missing",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class ContactInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public bool RecordExists { get; set; }
    public string ContactRecord { get; set; }
    public IReadOnlyDictionary<string, string> Fields { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public ContactInfoAnalysis Raw { get; set; }
}
