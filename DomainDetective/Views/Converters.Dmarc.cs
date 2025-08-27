using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DmarcRecordInfo Convert(DmarcAnalysis analysis)
    {
        return new DmarcRecordInfo
        {
            DmarcRecord = analysis.DmarcRecord,
            DmarcRecordExists = analysis.DmarcRecordExists,
            StartsCorrectly = analysis.StartsCorrectly,
            IsPolicyValid = analysis.IsPolicyValid,
            Policy = analysis.Policy,
            SubPolicy = analysis.SubPolicy,
            NonexistentPolicy = analysis.NonexistentPolicy,
            PublicSuffixPolicy = analysis.PublicSuffixPolicy,
            ReportFeedback = analysis.ReportFeedback,
            Percent = analysis.Percent,
            DkimAlignment = analysis.DkimAlignment,
            SpfAlignment = analysis.SpfAlignment,
            Rua = analysis.Rua,
            Ruf = analysis.Ruf,
            MailtoRua = analysis.MailtoRua,
            HttpRua = analysis.HttpRua,
            MailtoRuf = analysis.MailtoRuf,
            HttpRuf = analysis.HttpRuf,
            ExternalReportAuthorization = analysis.ExternalReportAuthorization,
            InvalidReportUri = analysis.InvalidReportUri,
            DeprecatedTags = analysis.DeprecatedTags,
            Assessments = analysis.Assessments,
            Recommendations = analysis.Recommendations,
            References = BuildReferences(System.Array.Empty<StandardReference>(), analysis.Recommendations),
            Raw = analysis
        };
    }
}

public class DmarcRecordInfo
{
    public string DmarcRecord { get; set; }
    public bool DmarcRecordExists { get; set; }
    public bool StartsCorrectly { get; set; }
    public bool IsPolicyValid { get; set; }
    public string Policy { get; set; }
    public string SubPolicy { get; set; }
    public string NonexistentPolicy { get; set; }
    public string PublicSuffixPolicy { get; set; }
    public string ReportFeedback { get; set; }
    public string Percent { get; set; }
    public string DkimAlignment { get; set; }
    public string SpfAlignment { get; set; }
    public string Rua { get; set; }
    public string Ruf { get; set; }
    public IReadOnlyList<string> MailtoRua { get; set; }
    public IReadOnlyList<string> HttpRua { get; set; }
    public IReadOnlyList<string> MailtoRuf { get; set; }
    public IReadOnlyList<string> HttpRuf { get; set; }
    public IReadOnlyDictionary<string, bool> ExternalReportAuthorization { get; set; }
    public bool InvalidReportUri { get; set; }
    public IReadOnlyList<string> DeprecatedTags { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public DmarcAnalysis Raw { get; set; }
}

