using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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

/// <summary>Provides rdap info functionality.</summary>
public class RdapInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string Subject { get; set; } = null!;
    /// <summary>Gets or sets the unicode name value.</summary>
    public string? UnicodeName { get; set; }
    /// <summary>Gets or sets the handle value.</summary>
    public string? Handle { get; set; }
    /// <summary>Gets or sets the registrar value.</summary>
    public string? Registrar { get; set; }
    /// <summary>Gets or sets the registrar id value.</summary>
    public string? RegistrarId { get; set; }
    /// <summary>Gets or sets the creation date value.</summary>
    public string? CreationDate { get; set; }
    /// <summary>Gets or sets the expiry date value.</summary>
    public string? ExpiryDate { get; set; }
    /// <summary>Gets or sets the days until expiration value.</summary>
    public int? DaysUntilExpiration { get; set; }
    /// <summary>Gets or sets the name servers value.</summary>
    public IReadOnlyList<string> NameServers { get; set; } = null!;
    /// <summary>Gets or sets the status values value.</summary>
    public IReadOnlyList<string> StatusValues { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the record available value.</summary>
    public bool RecordAvailable { get; set; }
    /// <summary>Gets or sets the has contact entity value.</summary>
    public bool HasContactEntity { get; set; }
    /// <summary>Gets or sets the has hold status value.</summary>
    public bool HasHoldStatus { get; set; }
    /// <summary>Gets or sets the entity summaries value.</summary>
    public IReadOnlyList<RdapEntitySummary> EntitySummaries { get; set; } = System.Array.Empty<RdapEntitySummary>();
    /// <summary>Gets or sets the event summaries value.</summary>
    public IReadOnlyList<RdapEventSummary> EventSummaries { get; set; } = System.Array.Empty<RdapEventSummary>();
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = null!;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = null!;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = null!;
    /// <summary>Gets or sets the raw value.</summary>
    [JsonIgnore]
    public RdapAnalysis Raw { get; set; } = null!;
}

/// <summary>Provides rdap entity summary functionality.</summary>
public sealed class RdapEntitySummary
{
    /// <summary>Gets or sets the handle value.</summary>
    public string? Handle { get; set; }
    /// <summary>Gets or sets the roles value.</summary>
    public IReadOnlyList<string> Roles { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the status values value.</summary>
    public IReadOnlyList<string> StatusValues { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the has vcard value.</summary>
    public bool HasVcard { get; set; }
}

/// <summary>Provides rdap event summary functionality.</summary>
public sealed class RdapEventSummary
{
    /// <summary>Gets or sets the action value.</summary>
    public string Action { get; set; } = string.Empty;
    /// <summary>Gets or sets the date value.</summary>
    public string? Date { get; set; }
    /// <summary>Gets or sets the parsed date value.</summary>
    public DateTimeOffset? ParsedDate { get; set; }
}
