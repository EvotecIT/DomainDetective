using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static RdapInfo Convert(RdapAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var entitySummaries = BuildEntitySummaries(analysis.DomainData);
        var eventSummaries = BuildEventSummaries(analysis.DomainData);
        var expiry = ParseDateOrNull(analysis.ExpiryDate) ?? eventSummaries
            .Where(static item => string.Equals(item.Action, RdapEventAction.Expiration.ToString(), StringComparison.OrdinalIgnoreCase))
            .Select(static item => item.ParsedDate)
            .FirstOrDefault(static item => item.HasValue);
        return new RdapInfo
        {
            Check = HealthCheckType.RDAP,
            Area = AreaForKind(HealthCheckType.RDAP),
            Subject = analysis.DomainName,
            UnicodeName = analysis.DomainData?.UnicodeName,
            Handle = analysis.DomainData?.Handle,
            Registrar = analysis.Registrar,
            RegistrarId = analysis.RegistrarId,
            CreationDate = analysis.CreationDate,
            ExpiryDate = analysis.ExpiryDate,
            DaysUntilExpiration = expiry.HasValue ? (int?)Math.Ceiling((expiry.Value - DateTimeOffset.UtcNow).TotalDays) : null,
            NameServers = analysis.NameServers,
            StatusValues = analysis.Status?.Select(static value => value.ToString()).ToArray() ?? System.Array.Empty<string>(),
            RecordAvailable = analysis.DomainData != null,
            HasContactEntity = analysis.Assessments.Any(static assessment => string.Equals(assessment.Code, DomainDetective.RdapCodes.ContactValid, StringComparison.OrdinalIgnoreCase)),
            HasHoldStatus = analysis.Status?.Any(static value => value == RdapDomainStatus.ClientHold || value == RdapDomainStatus.ServerHold) == true,
            EntitySummaries = entitySummaries,
            EventSummaries = eventSummaries,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"registrar {(analysis.Registrar ?? "?")}; expires {analysis.ExpiryDate ?? "?"}",
            Assessments = analysis.Assessments,
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc7483" },
            Raw = analysis
        };
    }

    private static List<RdapEntitySummary> BuildEntitySummaries(RdapDomain? domainData)
    {
        var entities = new List<RdapEntitySummary>();
        if (domainData?.Entities == null)
        {
            return entities;
        }

        foreach (var entity in domainData.Entities)
        {
            if (entity == null)
            {
                continue;
            }

            entities.Add(new RdapEntitySummary
            {
                Handle = entity.Handle,
                Roles = entity.Roles?.Where(static role => !string.IsNullOrWhiteSpace(role)).ToArray() ?? Array.Empty<string>(),
                StatusValues = entity.Status?.Where(static value => value != RdapDomainStatus.Unknown).Select(static value => value.ToString()).ToArray() ?? Array.Empty<string>(),
                HasVcard = entity.VcardArray.HasValue
            });
        }

        return entities;
    }

    private static List<RdapEventSummary> BuildEventSummaries(RdapDomain? domainData)
    {
        var events = new List<RdapEventSummary>();
        if (domainData?.Events == null)
        {
            return events;
        }

        foreach (var item in domainData.Events)
        {
            if (item == null)
            {
                continue;
            }

            events.Add(new RdapEventSummary
            {
                Action = item.Action.ToString(),
                Date = item.Date,
                ParsedDate = ParseDateOrNull(item.Date)
            });
        }

        return events;
    }

    private static DateTimeOffset? ParseDateOrNull(string? value)
    {
        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
        {
            return parsed;
        }

        return null;
    }
}

public class RdapInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = null!;
    public string? UnicodeName { get; set; }
    public string? Handle { get; set; }
    public string? Registrar { get; set; }
    public string? RegistrarId { get; set; }
    public string? CreationDate { get; set; }
    public string? ExpiryDate { get; set; }
    public int? DaysUntilExpiration { get; set; }
    public IReadOnlyList<string> NameServers { get; set; } = null!;
    public IReadOnlyList<string> StatusValues { get; set; } = System.Array.Empty<string>();
    public bool RecordAvailable { get; set; }
    public bool HasContactEntity { get; set; }
    public bool HasHoldStatus { get; set; }
    public IReadOnlyList<RdapEntitySummary> EntitySummaries { get; set; } = System.Array.Empty<RdapEntitySummary>();
    public IReadOnlyList<RdapEventSummary> EventSummaries { get; set; } = System.Array.Empty<RdapEventSummary>();
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    [JsonIgnore]
    public RdapAnalysis Raw { get; set; } = null!;
}

public sealed class RdapEntitySummary
{
    public string? Handle { get; set; }
    public IReadOnlyList<string> Roles { get; set; } = Array.Empty<string>();
    public IReadOnlyList<string> StatusValues { get; set; } = Array.Empty<string>();
    public bool HasVcard { get; set; }
}

public sealed class RdapEventSummary
{
    public string Action { get; set; } = string.Empty;
    public string? Date { get; set; }
    public DateTimeOffset? ParsedDate { get; set; }
}
