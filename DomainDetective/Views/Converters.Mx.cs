using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static MxInfo Convert(MXAnalysis analysis)
    {
        // MXAnalysis doesn't emit assessments yet; summarize will return OK/0/0
        Summarize(analysis is IHasAssessments has ? has.Assessments : new List<Assessment>(), out var warnCount, out var errCount, out var status);
        var recs = analysis is IHasAssessments h2 ? RecommendationEngine.From(h2.Assessments) : new List<RecommendationAdvice>();
        return new MxInfo
        {
            Check = "MX",
            Area = AreaFor("MX"),
            Subject = analysis.Subject,
            MxRecords = analysis.MxRecords,
            MxRecordExists = analysis.MxRecordExists,
            PointsToCname = analysis.PointsToCname,
            PointsToIpAddress = analysis.PointsToIpAddress,
            PointsToNonExistentDomain = analysis.PointsToNonExistentDomain,
            PointsToDomainWithoutAOrAaaaRecord = analysis.PointsToDomainWithoutAOrAaaaRecord,
            PrioritiesInOrder = analysis.PrioritiesInOrder,
            HasBackupServers = analysis.HasBackupServers,
            HasNullMx = analysis.HasNullMx,
            PointsToLocalhost = analysis.PointsToLocalhost,
            Assessments = analysis is IHasAssessments h ? h.Assessments : new List<Assessment>(),
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"{analysis.MxRecords?.Count ?? 0} MX; backup {(analysis.HasBackupServers ? "yes" : "no")}\u002c null-MX {(analysis.HasNullMx ? "yes" : "no")}",
            Recommendations = recs,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc5321" },
            Raw = analysis
        };
    }
}

public class MxInfo
{
    public string Check { get; set; }
    public string Area { get; set; }
    public string Subject { get; set; }
    public IReadOnlyList<string> MxRecords { get; set; }
    public bool MxRecordExists { get; set; }
    public bool PointsToCname { get; set; }
    public bool PointsToIpAddress { get; set; }
    public bool PointsToNonExistentDomain { get; set; }
    public bool PointsToDomainWithoutAOrAaaaRecord { get; set; }
    public bool PrioritiesInOrder { get; set; }
    public bool HasBackupServers { get; set; }
    public bool HasNullMx { get; set; }
    public bool PointsToLocalhost { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public MXAnalysis Raw { get; set; }
}
