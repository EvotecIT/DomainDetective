using DomainDetective.Helpers;
using DomainDetective.Network;
using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

/// <summary>
/// Summarizes DNS propagation query results for reporting (composition).
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DnsPropagationReportAnalysis : IHasAssessments
{
    /// <summary>Domain being analyzed.</summary>
    public string? Subject { get; private set; }

    /// <summary>Record type tested across resolvers.</summary>
    public DnsRecordType RecordType { get; private set; }

    /// <summary>True when at least one successful answer was observed.</summary>
    public bool QuerySucceeded { get; private set; }

    /// <summary>Total servers queried.</summary>
    public int ServerCount { get; private set; }

    /// <summary>Number of servers that returned at least one answer.</summary>
    public int SuccessCount { get; private set; }

    /// <summary>Number of servers that failed or returned no answers.</summary>
    public int ErrorCount { get; private set; }

    /// <summary>Number of distinct answer sets observed.</summary>
    public int DistinctAnswerSets { get; private set; }

    /// <summary>Normalized majority answer set key (joined by comma).</summary>
    public string? MajorityAnswerSet { get; private set; }

    /// <summary>Minimum observed query duration.</summary>
    public TimeSpan? MinDuration { get; private set; }

    /// <summary>Maximum observed query duration.</summary>
    public TimeSpan? MaxDuration { get; private set; }

    /// <summary>Average observed query duration.</summary>
    public TimeSpan? AvgDuration { get; private set; }

    /// <summary>True when the retained results were capped for reporting.</summary>
    public bool ResultsCapped { get; private set; }

    /// <summary>Retained server results (may be capped).</summary>
    public IReadOnlyList<DnsPropagationResult> Results { get; private set; } = Array.Empty<DnsPropagationResult>();

    /// <summary>Assessment collection for report-friendly output.</summary>
    public List<Assessment> Assessments { get; } = new();

    /// <summary>Represents the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    /// <summary>Relevant standards for DNS propagation.</summary>
    public IReadOnlyList<StandardReference> References => new[]
    {
        new StandardReference { Title = "Domain Names - Concepts and Facilities", Reference = "RFC 1034", Url = "https://www.rfc-editor.org/rfc/rfc1034" },
        new StandardReference { Title = "Domain Names - Implementation and Specification", Reference = "RFC 1035", Url = "https://www.rfc-editor.org/rfc/rfc1035" }
    };

    /// <summary>
    /// Loads and summarizes already-collected propagation <paramref name="results"/>.
    /// </summary>
    public void Load(string domain, DnsRecordType recordType, IReadOnlyList<DnsPropagationResult> results, int maxResultsToKeep = 500)
    {
        if (string.IsNullOrWhiteSpace(domain)) throw new ArgumentNullException(nameof(domain));

        Reset();
        Subject = DomainHelper.ValidateIdn(domain);
        RecordType = recordType;

        var safe = results ?? Array.Empty<DnsPropagationResult>();
        ServerCount = safe.Count;
        if (ServerCount == 0)
        {
            QuerySucceeded = false;
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "DNS Propagation",
                Code = DnsPropagationCodes.NoServersSelected,
                Target = Subject,
                Message = "No DNS servers were selected for propagation testing."
            });
            Results = Array.Empty<DnsPropagationResult>();
            return;
        }

        var durations = safe.Select(r => r?.Duration ?? TimeSpan.Zero).Where(ts => ts > TimeSpan.Zero).ToList();
        if (durations.Count > 0)
        {
            MinDuration = durations.Min();
            MaxDuration = durations.Max();
            AvgDuration = TimeSpan.FromMilliseconds(durations.Average(d => d.TotalMilliseconds));
        }

        SuccessCount = safe.Count(r => r != null && r.Success);
        ErrorCount = ServerCount - SuccessCount;

        QuerySucceeded = SuccessCount > 0;
        if (!QuerySucceeded)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Error,
                Category = "DNS Propagation",
                Code = DnsPropagationCodes.QueryFailed,
                Target = Subject,
                Message = "All propagation queries failed or returned no answers."
            });
        }
        else
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Category = "DNS Propagation",
                Code = DnsPropagationCodes.ResultsPresent,
                Target = Subject,
                Message = $"Propagation results collected from {ServerCount} server(s)."
            });
        }

        if (ErrorCount > 0)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "DNS Propagation",
                Code = DnsPropagationCodes.ErrorsPresent,
                Target = Subject,
                Message = $"{ErrorCount} server(s) failed or returned no answers."
            });
        }

        try
        {
            var groups = DnsPropagationAnalysis.CompareResults(safe);
            DistinctAnswerSets = groups.Count;
            MajorityAnswerSet = groups
                .OrderByDescending(kv => kv.Value?.Count ?? 0)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Select(kv => kv.Key)
                .FirstOrDefault();

            if (DistinctAnswerSets > 1)
            {
                Assessments.Add(new Assessment
                {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DNS Propagation",
                    Code = DnsPropagationCodes.InconsistentAnswers,
                    Target = Subject,
                    Message = $"Inconsistent DNS answers observed across resolvers ({DistinctAnswerSets} distinct answer set(s))."
                });
            }
            else if (DistinctAnswerSets == 1 && QuerySucceeded)
            {
                Assessments.Add(new Assessment
                {
                    Severity = AssessmentSeverity.Info,
                    Category = "DNS Propagation",
                    Code = DnsPropagationCodes.ConsistentAnswers,
                    Target = Subject,
                    Message = "All successful resolvers returned the same answer set."
                });
            }
        }
        catch
        {
        }

        // Private/non-public IP and split-horizon signals (A/AAAA only)
        try
        {
            if (recordType == DnsRecordType.A || recordType == DnsRecordType.AAAA)
            {
                bool anyPublic = false;
                bool anyNonPublic = false;
                var nonPublicEvidence = new List<string>();

                foreach (var r in safe.Where(r => r != null && r.Success))
                {
                    foreach (var rec in r.Records ?? Array.Empty<string>())
                    {
                        if (!IpAddressClassifier.TryClassify(rec, out var vis))
                        {
                            continue;
                        }

                        if (IpAddressClassifier.IsNonPublic(vis))
                        {
                            anyNonPublic = true;
                            if (nonPublicEvidence.Count < 6)
                            {
                                var server = r.Server?.HostName ?? r.Server?.IPAddress?.ToString() ?? "resolver";
                                nonPublicEvidence.Add($"{server}: {rec} ({vis})");
                            }
                        }
                        else
                        {
                            anyPublic = true;
                        }
                    }
                }

                if (anyNonPublic)
                {
                    Assessments.Add(new Assessment
                    {
                        Severity = AssessmentSeverity.Warning,
                        Category = "DNS Propagation",
                        Code = DnsPropagationCodes.NonPublicIpAddress,
                        Target = Subject,
                        Message = nonPublicEvidence.Count > 0
                            ? $"Non-public IP address(es) observed via public resolvers: {string.Join(", ", nonPublicEvidence)}"
                            : "Non-public IP address(es) observed via public resolvers."
                    });
                }

                if (anyPublic && anyNonPublic)
                {
                    Assessments.Add(new Assessment
                    {
                        Severity = AssessmentSeverity.Warning,
                        Category = "DNS Propagation",
                        Code = DnsPropagationCodes.SplitHorizonSuspected,
                        Target = Subject,
                        Message = "Mixed public and non-public A/AAAA answers observed across resolvers (possible split-horizon or DNS manipulation)."
                    });
                }
            }
        }
        catch
        {
        }

        // Cap retained results for reporting (keeps HTML/Word/Excel manageable).
        if (maxResultsToKeep > 0 && safe.Count > maxResultsToKeep)
        {
            ResultsCapped = true;
            Results = safe.Take(maxResultsToKeep).ToList();
        }
        else
        {
            Results = safe.ToList();
        }
    }

    private void Reset()
    {
        Subject = null;
        RecordType = default;
        QuerySucceeded = false;
        ServerCount = 0;
        SuccessCount = 0;
        ErrorCount = 0;
        DistinctAnswerSets = 0;
        MajorityAnswerSet = null;
        MinDuration = null;
        MaxDuration = null;
        AvgDuration = null;
        ResultsCapped = false;
        Results = Array.Empty<DnsPropagationResult>();
        Assessments.Clear();
    }
}
