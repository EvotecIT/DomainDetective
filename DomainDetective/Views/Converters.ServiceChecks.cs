using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Converts a robots.txt analysis into its report view.</summary>
    public static RobotsTxtInfo Convert(RobotsTxtAnalysis analysis)
    {
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        Summarize(analysis.Assessments, out var warn, out var err, out var status);
        return new RobotsTxtInfo
        {
            Check = HealthCheckType.ROBOTS,
            Area = AreaForKind(HealthCheckType.ROBOTS),
            Subject = analysis.Domain ?? string.Empty,
            RecordPresent = analysis.RecordPresent,
            FallbackUsed = analysis.FallbackUsed,
            Url = analysis.Url ?? string.Empty,
            UserAgentGroups = analysis.Robots?.Groups.Count ?? 0,
            Sitemaps = analysis.Robots?.Sitemaps.ToList() ?? new List<string>(),
            AiBotRules = analysis.AiBots
                .Where(static bot => bot.Value.Count > 0)
                .Select(static bot => $"{bot.Key}: {string.Join(", ", bot.Value)}")
                .ToList(),
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = err,
            Summary = analysis.RecordPresent ? "robots.txt published" : "robots.txt not found",
            Recommendations = recs,
            Positives = RecommendationEngine.FromPositives(analysis.Assessments),
            References = BuildReferences(Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }

    /// <summary>Converts an HTTP public key pinning analysis into its report view.</summary>
    public static HpkpInfo Convert(HPKPAnalysis analysis)
    {
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        Summarize(analysis.Assessments, out var warn, out var err, out var status);
        return new HpkpInfo
        {
            Check = HealthCheckType.HPKP,
            Area = AreaForKind(HealthCheckType.HPKP),
            Subject = analysis.Subject ?? string.Empty,
            HeaderPresent = analysis.HeaderPresent,
            PinsValid = analysis.PinsValid,
            MaxAge = analysis.MaxAge,
            IncludesSubDomains = analysis.IncludesSubDomains,
            Pins = analysis.Pins.ToList(),
            Header = analysis.Header ?? string.Empty,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = err,
            // HPKP is deprecated; not sending the header is the expected state.
            Summary = analysis.HeaderPresent ? "Public-Key-Pins header sent" : "No Public-Key-Pins header",
            Recommendations = recs,
            Positives = RecommendationEngine.FromPositives(analysis.Assessments),
            References = BuildReferences(Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }

    /// <summary>Converts an SNMP exposure analysis into its report view.</summary>
    public static SnmpInfo Convert(SnmpAnalysis analysis)
    {
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        Summarize(analysis.Assessments, out var warn, out var err, out var status);
        int responding = analysis.ServerResults.Count(static r => r.Value);
        return new SnmpInfo
        {
            Check = HealthCheckType.SNMP,
            Area = AreaForKind(HealthCheckType.SNMP),
            Subject = analysis.Subject ?? analysis.ServerResults.Keys.FirstOrDefault() ?? string.Empty,
            Servers = analysis.ServerResults.Select(static r => new ServiceProbeResult { Endpoint = r.Key, Responded = r.Value }).ToList(),
            RespondingServers = responding,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = err,
            Summary = responding > 0 ? $"SNMP answered on {responding.ToString(CultureInfo.InvariantCulture)} endpoint(s)" : "SNMP not answering",
            Recommendations = recs,
            Positives = RecommendationEngine.FromPositives(analysis.Assessments),
            References = BuildReferences(Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }

    /// <summary>Converts an NTP server analysis into its report view.</summary>
    public static NtpInfo Convert(NtpAnalysis analysis)
    {
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        Summarize(analysis.Assessments, out var warn, out var err, out var status);
        int answering = analysis.ServerResults.Count(static r => r.Value.Success);
        return new NtpInfo
        {
            Check = HealthCheckType.NTP,
            Area = AreaForKind(HealthCheckType.NTP),
            Subject = analysis.ServerResults.Keys.FirstOrDefault() ?? string.Empty,
            Servers = analysis.ServerResults.Select(static r => new NtpServerInfo
            {
                Server = r.Key,
                Answered = r.Value.Success,
                OffsetMilliseconds = r.Value.Success ? Math.Round(r.Value.Offset.TotalMilliseconds, 1) : null,
                Stratum = r.Value.Success ? r.Value.Stratum : null
            }).ToList(),
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = err,
            Summary = answering > 0 ? $"NTP answered on {answering.ToString(CultureInfo.InvariantCulture)} server(s)" : "NTP not answering",
            Recommendations = recs,
            Positives = RecommendationEngine.FromPositives(analysis.Assessments),
            References = BuildReferences(Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }

    /// <summary>Converts a CNAME flattening service analysis into its report view.</summary>
    public static FlatteningServiceInfo Convert(FlatteningServiceAnalysis analysis)
    {
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        Summarize(analysis.Assessments, out var warn, out var err, out var status);
        return new FlatteningServiceInfo
        {
            Check = HealthCheckType.FLATTENINGSERVICE,
            Area = AreaForKind(HealthCheckType.FLATTENINGSERVICE),
            Subject = analysis.Subject ?? string.Empty,
            CnameRecordExists = analysis.CnameRecordExists,
            Target = analysis.Target ?? string.Empty,
            IsFlatteningService = analysis.IsFlatteningService,
            Addresses = analysis.Addresses.ToList(),
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = err,
            Summary = analysis.IsFlatteningService ? $"Apex flattened through {analysis.Target}" : "No CNAME flattening service",
            Recommendations = recs,
            Positives = RecommendationEngine.FromPositives(analysis.Assessments),
            References = BuildReferences(Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

/// <summary>Common members of the service-check views below.</summary>
public abstract class ServiceCheckInfo
{
    /// <summary>Type of health check.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Logical analysis area.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Subject domain or host.</summary>
    public string Subject { get; set; } = string.Empty;
    /// <summary>Assessment list.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    /// <summary>Overall status (OK/Warning/Error).</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Number of warnings.</summary>
    public int WarningCount { get; set; }
    /// <summary>Number of errors.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Short summary text.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Actionable recommendations.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = Array.Empty<RecommendationAdvice>();
    /// <summary>Positive posture notes.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = Array.Empty<RecommendationAdvice>();
    /// <summary>Reference links.</summary>
    public IReadOnlyList<string> References { get; set; } = Array.Empty<string>();
}

/// <summary>robots.txt publication and AI crawler rules.</summary>
public sealed class RobotsTxtInfo : ServiceCheckInfo
{
    /// <summary>Whether robots.txt was found.</summary>
    public bool RecordPresent { get; set; }
    /// <summary>Whether the file came from a fallback location.</summary>
    public bool FallbackUsed { get; set; }
    /// <summary>Address the file was read from.</summary>
    public string Url { get; set; } = string.Empty;
    /// <summary>Number of user-agent groups.</summary>
    public int UserAgentGroups { get; set; }
    /// <summary>Sitemaps listed in the file.</summary>
    public IReadOnlyList<string> Sitemaps { get; set; } = Array.Empty<string>();
    /// <summary>Rules that apply to known AI crawlers.</summary>
    public IReadOnlyList<string> AiBotRules { get; set; } = Array.Empty<string>();
    /// <summary>Underlying analysis.</summary>
    public RobotsTxtAnalysis? Raw { get; set; }
}

/// <summary>HTTP public key pinning header (deprecated).</summary>
public sealed class HpkpInfo : ServiceCheckInfo
{
    /// <summary>Whether the header is sent.</summary>
    public bool HeaderPresent { get; set; }
    /// <summary>Whether the pins are well formed.</summary>
    public bool PinsValid { get; set; }
    /// <summary>max-age in seconds.</summary>
    public int MaxAge { get; set; }
    /// <summary>Whether includeSubDomains is set.</summary>
    public bool IncludesSubDomains { get; set; }
    /// <summary>Pinned key hashes.</summary>
    public IReadOnlyList<string> Pins { get; set; } = Array.Empty<string>();
    /// <summary>Raw header value.</summary>
    public string Header { get; set; } = string.Empty;
    /// <summary>Underlying analysis.</summary>
    public HPKPAnalysis? Raw { get; set; }
}

/// <summary>Result of probing one endpoint.</summary>
public sealed class ServiceProbeResult
{
    /// <summary>Endpoint (host:port).</summary>
    public string Endpoint { get; set; } = string.Empty;
    /// <summary>Whether the service answered.</summary>
    public bool Responded { get; set; }
}

/// <summary>SNMP exposure.</summary>
public sealed class SnmpInfo : ServiceCheckInfo
{
    /// <summary>Probed endpoints.</summary>
    public IReadOnlyList<ServiceProbeResult> Servers { get; set; } = Array.Empty<ServiceProbeResult>();
    /// <summary>Endpoints that answered.</summary>
    public int RespondingServers { get; set; }
    /// <summary>Underlying analysis.</summary>
    public SnmpAnalysis? Raw { get; set; }
}

/// <summary>One NTP server result.</summary>
public sealed class NtpServerInfo
{
    /// <summary>Server name.</summary>
    public string Server { get; set; } = string.Empty;
    /// <summary>Whether the server answered.</summary>
    public bool Answered { get; set; }
    /// <summary>Clock offset in milliseconds.</summary>
    public double? OffsetMilliseconds { get; set; }
    /// <summary>Stratum reported by the server.</summary>
    public int? Stratum { get; set; }
}

/// <summary>NTP service availability.</summary>
public sealed class NtpInfo : ServiceCheckInfo
{
    /// <summary>Probed servers.</summary>
    public IReadOnlyList<NtpServerInfo> Servers { get; set; } = Array.Empty<NtpServerInfo>();
    /// <summary>Underlying analysis.</summary>
    public NtpAnalysis? Raw { get; set; }
}

/// <summary>CNAME flattening at the zone apex.</summary>
public sealed class FlatteningServiceInfo : ServiceCheckInfo
{
    /// <summary>Whether the apex has a CNAME.</summary>
    public bool CnameRecordExists { get; set; }
    /// <summary>CNAME target.</summary>
    public string Target { get; set; } = string.Empty;
    /// <summary>Whether the target is a known flattening service.</summary>
    public bool IsFlatteningService { get; set; }
    /// <summary>Addresses the apex resolves to.</summary>
    public IReadOnlyList<string> Addresses { get; set; } = Array.Empty<string>();
    /// <summary>Underlying analysis.</summary>
    public FlatteningServiceAnalysis? Raw { get; set; }
}
