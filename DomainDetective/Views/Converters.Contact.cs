using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static ContactInfo Convert(ContactInfoAnalysis analysis)
    {
        // ContactInfoAnalysis does not surface assessments; derive simple status
        var assessments = new List<Assessment>();
        int warn = analysis.RecordExists ? 0 : 1;
        string status = analysis.RecordExists ? "OK" : "Warning";
        var recs = RecommendationEngine.From(assessments);
        return new ContactInfo
        {
            Check = "CONTACT",
            Area = AreaFor("CONTACT"),
            Subject = null,
            RecordExists = analysis.RecordExists,
            ContactRecord = analysis.ContactRecord,
            Fields = analysis.Fields,
            Assessments = assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = 0,
            Summary = analysis.RecordExists ? "present" : "missing",
            Recommendations = recs,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class ContactInfo
{
    public string Check { get; set; }
    public string Area { get; set; }
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
    public IReadOnlyList<string> References { get; set; }
    public ContactInfoAnalysis Raw { get; set; }
}
