using DnsClientX;
using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Performs an authoritative-style DNS trace by iteratively querying root servers and following referrals.
/// Captures a hop-by-hop log to support explainability and debugging.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DnsTraceAnalysis : IHasAssessments
{
    /// <summary>The domain being analyzed.</summary>
    public string? Subject { get; private set; }

    /// <summary>DNS configuration (used for user-agent and shared defaults).</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>
    /// Optional override for querying a specific DNS server (IP) for (name,type).
    /// Used by tests and offline callers.
    /// </summary>
    public Func<string, string, DnsRecordType, CancellationToken, Task<DnsResponse>>? QueryOverride { get; set; }

    /// <summary>Record types to trace (default: A and AAAA).</summary>
    public DnsRecordType[] RecordTypesToTrace { get; set; } = new[] { DnsRecordType.A, DnsRecordType.AAAA };

    /// <summary>When true, includes IPv6 root servers in the initial hop set.</summary>
    public bool IncludeIpv6RootServers { get; set; }

    /// <summary>Maximum referral depth before stopping.</summary>
    public int MaxDepth { get; set; } = 12;

    /// <summary>Maximum servers tried per depth (prevents huge referral fan-out).</summary>
    public int MaxServersPerDepth { get; set; } = 4;

    /// <summary>Maximum total steps captured across all traced record types.</summary>
    public int MaxTotalSteps { get; set; } = 250;

    /// <summary>Maximum CNAME hops to chase when an authoritative response returns a CNAME without the requested type.</summary>
    public int MaxCnameHops { get; set; } = 5;

    /// <summary>Timeout per server query (milliseconds) for UDP/TCP fallback queries.</summary>
    public int TimeoutMilliseconds { get; set; } = 2500;

    /// <summary>True when tracing executed (even if a record type returned no final answer).</summary>
    public bool TraceSucceeded { get; private set; }

    /// <summary>If <see cref="TraceSucceeded"/> is false, contains a short reason.</summary>
    public string? FailureReason { get; private set; }

    /// <summary>Total number of trace queries attempted.</summary>
    public int TraceQueries { get; private set; }

    /// <summary>Number of trace queries that failed.</summary>
    public int TraceQueriesFailed { get; private set; }

    /// <summary>Total number of steps captured across all trace queries.</summary>
    public int TotalSteps { get; private set; }

    /// <summary>Per-record-type trace results.</summary>
    public IReadOnlyList<DnsTraceQuery> Queries { get; private set; } = Array.Empty<DnsTraceQuery>();

    /// <summary>Assessment collection for report-friendly output.</summary>
    public List<Assessment> Assessments { get; } = new();

    /// <summary>
    /// Performs a DNS trace for the specified <paramref name="domain"/>.
    /// </summary>
    public async Task AnalyzeAsync(string domain, InternalLogger? logger = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentNullException(nameof(domain));
        }

        Reset();
        Subject = DomainHelper.ValidateIdn(domain);

        var types = (RecordTypesToTrace ?? Array.Empty<DnsRecordType>())
            .Distinct()
            .ToArray();
        TraceQueries = types.Length;

        var results = new List<DnsTraceQuery>(types.Length);
        try
        {
            foreach (var t in types)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var q = await TraceOneAsync(Subject!, t, cancellationToken).ConfigureAwait(false);
                results.Add(q);

                TotalSteps = results.Sum(r => r.Steps.Count);
                if (TotalSteps >= MaxTotalSteps)
                {
                    break;
                }
            }

            TraceSucceeded = true;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            TraceSucceeded = false;
            FailureReason = ex.Message;
        }

        Queries = results;
        TraceQueriesFailed = results.Count(q => q.Status == DnsTraceQueryStatus.Failed);
        TotalSteps = results.Sum(r => r.Steps.Count);

        if (!TraceSucceeded)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Error,
                Category = "DNS Trace",
                Code = DnsTraceCodes.TraceFailed,
                Target = Subject,
                Message = $"DNS trace failed: {FailureReason}"
            });
            return;
        }

        if (TraceQueries == 0)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "DNS Trace",
                Code = DnsTraceCodes.NoQueries,
                Target = Subject,
                Message = "No record types were configured for DNS trace."
            });
            return;
        }

        foreach (var q in results.Where(r => r.Status == DnsTraceQueryStatus.Failed))
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "DNS Trace",
                Code = DnsTraceCodes.QueryFailed,
                Target = Subject,
                Message = $"{q.RecordType}: trace failed{(string.IsNullOrWhiteSpace(q.FailureReason) ? "." : $": {q.FailureReason}")}"
            });
        }

        if (TotalSteps == 0)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "DNS Trace",
                Code = DnsTraceCodes.NoSteps,
                Target = Subject,
                Message = "No trace steps were captured."
            });
        }
        else
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Category = "DNS Trace",
                Code = DnsTraceCodes.ResultsPresent,
                Target = Subject,
                Message = $"Captured {TotalSteps} trace step(s) across {results.Count} record type(s)."
            });
        }

        logger?.WriteVerbose("DNS trace captured {0} step(s) across {1} type(s) for {2}.", TotalSteps, results.Count, Subject);
    }

    private async Task<DnsTraceQuery> TraceOneAsync(string domain, DnsRecordType recordType, CancellationToken cancellationToken)
    {
        var q = new DnsTraceQuery
        {
            RecordType = recordType,
            OriginalName = domain,
            FinalName = domain,
            Status = DnsTraceQueryStatus.NoData
        };

        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _ = await ResolveIterativelyAsync(domain, recordType, DnsTraceStepKind.Query, q, Math.Max(1, MaxDepth), 0, visited, cancellationToken).ConfigureAwait(false);
        return q;
    }

    private async Task<DnsResponse?> ResolveIterativelyAsync(
        string name,
        DnsRecordType recordType,
        DnsTraceStepKind kind,
        DnsTraceQuery q,
        int remainingDepth,
        int cnameHops,
        HashSet<string> visited,
        CancellationToken cancellationToken)
    {
        if (remainingDepth <= 0)
        {
            return null;
        }

        var rootServers = GetInitialRootServers();
        var servers = rootServers;
        var current = NormalizeHost(name);
        DnsResponse? lastResponse = null;

        for (int depth = 0; depth < remainingDepth; depth++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            bool progressed = false;
            var tryServers = servers.Take(Math.Max(1, MaxServersPerDepth)).ToList();
            foreach (var server in tryServers)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (q.Steps.Count >= MaxTotalSteps)
                {
                    q.Status = DnsTraceQueryStatus.Capped;
                    q.FailureReason = "Trace step cap reached.";
                    return lastResponse;
                }

                var key = $"{kind}|{server}|{current}|{recordType}";
                if (!visited.Add(key))
                {
                    continue;
                }

                var resp = await QueryServerAsync(server, current, recordType, cancellationToken).ConfigureAwait(false);
                lastResponse = resp;
                if (kind == DnsTraceStepKind.Query)
                {
                    q.FinalName = current;
                    q.FinalResponseStatus = resp.Status;
                }
                q.Steps.Add(BuildStep(kind, depth, server, current, recordType, resp));

                if (HasAnswerOfType(resp, recordType))
                {
                    if (kind == DnsTraceStepKind.Query)
                    {
                        q.Status = DnsTraceQueryStatus.Success;
                    }
                    return resp;
                }

                if (recordType != DnsRecordType.CNAME && TryGetCnameTarget(resp, out var cnameTarget))
                {
                    if (cnameHops >= Math.Max(0, MaxCnameHops))
                    {
                        if (kind == DnsTraceStepKind.Query)
                        {
                            q.Status = DnsTraceQueryStatus.NoData;
                            q.FailureReason = "CNAME hop cap reached.";
                        }
                        return resp;
                    }

                    cnameHops++;
                    current = cnameTarget;
                    if (kind == DnsTraceStepKind.Query)
                    {
                        q.CnameTargets.Add(cnameTarget);
                    }
                    servers = rootServers;
                    progressed = true;
                    depth = -1;
                    break;
                }

                var nextServers = ExtractReferralAddresses(resp);
                if (nextServers.Count > 0)
                {
                    servers = nextServers;
                    progressed = true;
                    break;
                }

                var nsNames = ExtractAuthorityNameServers(resp);
                if (nsNames.Count > 0 && remainingDepth - depth - 1 > 0)
                {
                    var nsResponse = await ResolveIterativelyAsync(nsNames[0], DnsRecordType.A, DnsTraceStepKind.NameServerLookup, q, remainingDepth - depth - 1, 0, visited, cancellationToken).ConfigureAwait(false);
                    var nsServers = nsResponse != null ? ExtractAnswerAddresses(nsResponse) : Array.Empty<string>();
                    if (nsServers.Count > 0)
                    {
                        servers = nsServers;
                        progressed = true;
                        break;
                    }
                }

                if (resp.Status == DnsResponseCode.NXDomain)
                {
                    if (kind == DnsTraceStepKind.Query)
                    {
                        q.Status = DnsTraceQueryStatus.NoData;
                        q.FailureReason = "NXDOMAIN.";
                    }
                    return resp;
                }
            }

            if (q.Status == DnsTraceQueryStatus.Capped)
            {
                return lastResponse;
            }

            if (!progressed)
            {
                break;
            }
        }

        if (kind == DnsTraceStepKind.Query && q.Status != DnsTraceQueryStatus.Success && q.Status != DnsTraceQueryStatus.Capped)
        {
            q.Status = DnsTraceQueryStatus.NoData;
            if (string.IsNullOrWhiteSpace(q.FailureReason) && lastResponse != null && lastResponse.Status != DnsResponseCode.NoError)
            {
                q.FailureReason = lastResponse.Status.ToString();
            }
        }

        return lastResponse;
    }

    private async Task<DnsResponse> QueryServerAsync(string server, string name, DnsRecordType type, CancellationToken cancellationToken)
    {
        if (QueryOverride != null)
        {
            return await QueryOverride(server, name, type, cancellationToken).ConfigureAwait(false);
        }

        using var client = new ClientX(server, DnsRequestFormat.DnsOverUDP, timeOutMilliseconds: TimeoutMilliseconds, userAgent: DnsConfiguration.UserAgent, useTcpFallback: true);
        var resp = await client.Resolve(name, type, retryOnTransient: false, maxRetries: 1, cancellationToken: cancellationToken).ConfigureAwait(false);
        return resp ?? new DnsResponse();
    }

    private static DnsTraceStep BuildStep(DnsTraceStepKind kind, int depth, string server, string name, DnsRecordType type, DnsResponse resp)
    {
        var next = ExtractReferralAddresses(resp);
        var ns = ExtractAuthorityNameServers(resp);
        TryGetCnameTarget(resp, out var cname);

        return new DnsTraceStep
        {
            Kind = kind,
            Depth = depth,
            Server = server,
            QueryName = name,
            RecordType = type,
            ResponseStatus = resp.Status,
            AnswerCount = resp.Answers?.Length ?? 0,
            AuthorityCount = resp.Authorities?.Length ?? 0,
            AdditionalCount = resp.Additional?.Length ?? 0,
            RoundTripTimeMs = (int)Math.Round(resp.RoundTripTime.TotalMilliseconds),
            CnameTarget = cname,
            ReferralNameServers = ns,
            NextServers = next
        };
    }

    private static bool HasAnswerOfType(DnsResponse resp, DnsRecordType recordType)
    {
        try
        {
            return resp.Answers != null && resp.Answers.Any(a => a.Type == recordType);
        }
        catch
        {
            return false;
        }
    }

    private static bool TryGetCnameTarget(DnsResponse resp, out string cnameTarget)
    {
        cnameTarget = string.Empty;
        try
        {
            var a = resp.Answers?.FirstOrDefault(x => x.Type == DnsRecordType.CNAME);
            if (a.HasValue)
            {
                var t = NormalizeHost(a.Value.DataRaw);
                if (!string.IsNullOrWhiteSpace(t))
                {
                    cnameTarget = t;
                    return true;
                }
            }
        }
        catch
        {
        }
        return false;
    }

    private static IReadOnlyList<string> ExtractAuthorityNameServers(DnsResponse resp)
    {
        var list = new List<string>();
        try
        {
            foreach (var a in resp.Authorities ?? Array.Empty<DnsAnswer>())
            {
                if (a.Type != DnsRecordType.NS)
                {
                    continue;
                }

                var ns = NormalizeHost(a.DataRaw);
                if (!string.IsNullOrWhiteSpace(ns) && !list.Contains(ns, StringComparer.OrdinalIgnoreCase))
                {
                    list.Add(ns);
                    if (list.Count >= 8)
                    {
                        break;
                    }
                }
            }
        }
        catch
        {
        }
        return list;
    }

    private static IReadOnlyList<string> ExtractReferralAddresses(DnsResponse resp)
    {
        var list = new List<string>();
        try
        {
            foreach (var a in resp.Additional ?? Array.Empty<DnsAnswer>())
            {
                if (a.Type != DnsRecordType.A && a.Type != DnsRecordType.AAAA)
                {
                    continue;
                }

                var ip = (a.DataRaw ?? string.Empty).Trim();
                if (!IPAddress.TryParse(ip, out _))
                {
                    continue;
                }

                if (!list.Contains(ip, StringComparer.OrdinalIgnoreCase))
                {
                    list.Add(ip);
                    if (list.Count >= 16)
                    {
                        break;
                    }
                }
            }
        }
        catch
        {
        }

        return list;
    }

    private static IReadOnlyList<string> ExtractAnswerAddresses(DnsResponse resp)
    {
        var list = new List<string>();
        try
        {
            foreach (var a in resp.Answers ?? Array.Empty<DnsAnswer>())
            {
                if (a.Type != DnsRecordType.A && a.Type != DnsRecordType.AAAA)
                {
                    continue;
                }

                var ip = (a.DataRaw ?? string.Empty).Trim();
                if (!IPAddress.TryParse(ip, out _))
                {
                    continue;
                }

                if (!list.Contains(ip, StringComparer.OrdinalIgnoreCase))
                {
                    list.Add(ip);
                    if (list.Count >= 16)
                    {
                        break;
                    }
                }
            }
        }
        catch
        {
        }
        return list;
    }

    private static string NormalizeHost(string? value)
    {
        var trimmed = (value ?? string.Empty).Trim().TrimEnd('.');
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        return trimmed.ToLowerInvariant();
    }

    private IReadOnlyList<string> GetInitialRootServers()
    {
        if (!IncludeIpv6RootServers)
        {
            return RootServersV4;
        }

        var list = new List<string>(RootServersV4.Length + RootServersV6.Length);
        list.AddRange(RootServersV4);
        list.AddRange(RootServersV6);
        return list;
    }

    private void Reset()
    {
        Subject = null;
        TraceSucceeded = false;
        FailureReason = null;
        TraceQueries = 0;
        TraceQueriesFailed = 0;
        TotalSteps = 0;
        Queries = Array.Empty<DnsTraceQuery>();
        Assessments.Clear();
    }

    private static readonly string[] RootServersV4 = new[]
    {
        "198.41.0.4",
        "199.9.14.201",
        "192.33.4.12",
        "199.7.91.13",
        "192.203.230.10",
        "192.5.5.241",
        "192.112.36.4",
        "198.97.190.53",
        "192.36.148.17",
        "192.58.128.30",
        "193.0.14.129",
        "199.7.83.42",
        "202.12.27.33"
    };

    private static readonly string[] RootServersV6 = new[]
    {
        "2001:503:ba3e::2:30",
        "2001:500:200::b",
        "2001:500:2::c",
        "2001:500:2d::d",
        "2001:500:a8::e",
        "2001:500:2f::f",
        "2001:500:12::d0d",
        "2001:500:1::53",
        "2001:7fe::53",
        "2001:503:c27::2:30",
        "2001:7fd::1",
        "2001:500:9f::42",
        "2001:dc3::35"
    };
}

public enum DnsTraceQueryStatus
{
    Success = 0,
    NoData = 1,
    Failed = 2,
    Capped = 3
}

public enum DnsTraceStepKind
{
    Query = 0,
    NameServerLookup = 1
}

public sealed class DnsTraceStep
{
    public DnsTraceStepKind Kind { get; init; }
    public int Depth { get; init; }
    public string Server { get; init; } = string.Empty;
    public string QueryName { get; init; } = string.Empty;
    public DnsRecordType RecordType { get; init; }
    public DnsResponseCode ResponseStatus { get; init; }
    public int AnswerCount { get; init; }
    public int AuthorityCount { get; init; }
    public int AdditionalCount { get; init; }
    public int RoundTripTimeMs { get; init; }
    public string? CnameTarget { get; init; }
    public IReadOnlyList<string> ReferralNameServers { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> NextServers { get; init; } = Array.Empty<string>();
}

public sealed class DnsTraceQuery
{
    public DnsRecordType RecordType { get; init; }
    public string OriginalName { get; init; } = string.Empty;
    public string FinalName { get; internal set; } = string.Empty;
    public DnsResponseCode FinalResponseStatus { get; internal set; }
    public DnsTraceQueryStatus Status { get; internal set; }
    public string? FailureReason { get; internal set; }
    public List<DnsTraceStep> Steps { get; } = new();

    /// <summary>Captured CNAME targets followed during trace (best-effort).</summary>
    public List<string> CnameTargets { get; } = new();
}
