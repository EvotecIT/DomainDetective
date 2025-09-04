using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Queries RDAP servers for domain registration data.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class RdapAnalysis : IHasAssessments
{
    private record CacheEntry(RdapDomain? Domain, DateTimeOffset Expires);
    private static readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Maximum time cached results are kept.</summary>
    public TimeSpan CacheDuration { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Clears the shared cache.</summary>
    public static void ClearCache() => _cache.Clear();
    /// <summary>Domain name returned by the RDAP server.</summary>
    public string DomainName { get; private set; } = string.Empty;
    /// <summary>Registrar display name.</summary>
    public string? Registrar { get; private set; }
    /// <summary>Registrar identifier.</summary>
    public string? RegistrarId { get; private set; }
    /// <summary>Domain creation date string.</summary>
    public string? CreationDate { get; private set; }
    /// <summary>Domain expiration date string.</summary>
    public string? ExpiryDate { get; private set; }
    /// <summary>List of authoritative name servers.</summary>
    public List<string> NameServers { get; private set; } = new();
    /// <summary>Status values reported by RDAP.</summary>
    public List<RdapDomainStatus> Status { get; private set; } = new();
    /// <summary>Deserialized RDAP domain data.</summary>
    public RdapDomain? DomainData { get; private set; }
    public List<Assessment> Assessments { get; } = new();

    internal Func<string, Task<string>>? QueryOverride { get; set; }

    /// <summary>
    /// RDAP client used for queries. Exposed internally for testing.
    /// </summary>
    internal RdapClient RdapClient { get; set; } = new();

    /// <summary>
    /// Retrieves RDAP information for <paramref name="domain"/>.
    /// </summary>
    /// <param name="domain">Domain to query.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    public async Task Analyze(string domain, InternalLogger? logger = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentNullException(nameof(domain));
        }

        DomainName = domain;
        Registrar = null;
        RegistrarId = null;
        CreationDate = null;
        ExpiryDate = null;
        NameServers = new List<string>();
        Status = new List<RdapDomainStatus>();

        if (_cache.TryGetValue(domain, out var cached) && cached.Expires > DateTimeOffset.UtcNow)
        {
            DomainData = cached.Domain;
        }
        else
        {
            RdapDomain? rdapResult;
            if (QueryOverride != null)
            {
                try
                {
                    var json = await QueryOverride(domain).ConfigureAwait(false);
                    rdapResult = JsonSerializer.Deserialize<RdapDomain>(json, RdapJson.Options);
                }
                catch (HttpRequestException ex)
                {
                    var url = $"{RdapClient.BaseUrl}/domain/{domain}";
#if NET6_0_OR_GREATER
                    var codeText = ex.StatusCode.HasValue
                        ? $"{(int)ex.StatusCode.Value} ({ex.StatusCode})"
                        : ex.Message;
                    logger?.WriteErrorCode(RdapCodes.RequestFailed, "RDAP request to {0} failed with status {1}", url, codeText);
                    if (ex.StatusCode == HttpStatusCode.NotFound)
                    {
                        rdapResult = null;
                    }
                    else
                    {
                        throw;
                    }
#else
                    logger?.WriteErrorCode(RdapCodes.RequestFailed, "RDAP request to {0} failed: {1}", url, ex.Message);
                    if (ex.Message.Contains("404"))
                    {
                        rdapResult = null;
                    }
                    else
                    {
                        throw;
                    }
#endif
                }
            }
            else
            {
                try
                {
                    rdapResult = await RdapClient.QueryDomainAsync(domain, cancellationToken).ConfigureAwait(false);
                }
                catch (HttpRequestException ex)
                {
                    var url = $"{RdapClient.BaseUrl}/domain/{domain}";
#if NET6_0_OR_GREATER
                    var codeText = ex.StatusCode.HasValue
                        ? $"{(int)ex.StatusCode.Value} ({ex.StatusCode})"
                        : ex.Message;
                    logger?.WriteErrorCode(RdapCodes.RequestFailed, "RDAP request to {0} failed with status {1}", url, codeText);
                    if (ex.StatusCode == HttpStatusCode.NotFound)
                    {
                        rdapResult = null;
                    }
                    else
                    {
                        throw;
                    }
#else
                    logger?.WriteErrorCode(RdapCodes.RequestFailed, "RDAP request to {0} failed: {1}", url, ex.Message);
                    if (ex.Message.Contains("404"))
                    {
                        rdapResult = null;
                    }
                    else
                    {
                        throw;
                    }
#endif
                }
            }

            DomainData = rdapResult;
            _cache[domain] = new CacheEntry(rdapResult, DateTimeOffset.UtcNow.Add(CacheDuration));
        }
        if (DomainData == null)
        {
            using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "RDAP", target: domain) : null;
            logger?.WriteWarningCode(RdapCodes.NotFound, "RDAP data not found for domain");
            return;
        }

        DomainName = DomainData.LdhName ?? DomainName;

        if (DomainData.Status != null)
        {
            Status = DomainData.Status
                .Where(s => s != RdapDomainStatus.Unknown)
                .ToList();
            // Emit status-based assessments for hold states
            if (Status.Contains(RdapDomainStatus.ClientHold) || Status.Contains(RdapDomainStatus.ServerHold))
            {
                using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "RDAP", target: DomainName) : null;
                logger?.WriteWarningCode(RdapCodes.StatusHold, "Domain is on hold (client/server)");
            }
        }

        if (DomainData.Nameservers != null)
        {
            NameServers = DomainData.Nameservers
                .Select(n => n.LdhName)
                .Where(n => !string.IsNullOrEmpty(n))
                .Select(n => n!)
                .ToList();
        }

        if (DomainData.Entities != null)
        {
            var hasContact = false;
            foreach (var ent in DomainData.Entities)
            {
                if (ent.Roles.Any(r => string.Equals(r, "registrar", StringComparison.OrdinalIgnoreCase)))
                {
                    RegistrarId ??= ent.Handle;
                    if (ent.VcardArray.HasValue && ent.VcardArray.Value.ValueKind == JsonValueKind.Array && ent.VcardArray.Value.GetArrayLength() > 1)
                    {
                        foreach (var card in ent.VcardArray.Value[1].EnumerateArray())
                        {
                            if (card.GetArrayLength() > 3 && card[0].GetString() == "fn")
                            {
                                Registrar = card[3].GetString();
                                break;
                            }
                        }
                    }
                }
                if (!hasContact && ent.VcardArray.HasValue && ent.VcardArray.Value.ValueKind == JsonValueKind.Array && ent.VcardArray.Value.GetArrayLength() > 1)
                {
                    foreach (var card in ent.VcardArray.Value[1].EnumerateArray())
                    {
                        if (card.GetArrayLength() > 3)
                        {
                            var t = card[0].GetString();
                            if ((t == "email" || t == "tel") && !string.IsNullOrWhiteSpace(card[3].GetString()))
                            {
                                hasContact = true;
                                break;
                            }
                        }
                    }
                }
            }
            if (hasContact)
            {
                using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "RDAP", target: DomainName) : null;
                logger?.WriteInformationCode(RdapCodes.ContactValid, "RDAP contact data present");
            }
        }

        if (DomainData.Events != null)
        {
            foreach (var ev in DomainData.Events)
            {
                if (ev.Action == RdapEventAction.Registration)
                {
                    CreationDate = ev.Date;
                }
                else if (ev.Action == RdapEventAction.Expiration)
                {
                    ExpiryDate = ev.Date;
                }
            }
            // Emit expiry soon when parsed
            if (!string.IsNullOrWhiteSpace(ExpiryDate) && DateTimeOffset.TryParse(ExpiryDate, out var exp))
            {
                var delta = exp - DateTimeOffset.UtcNow;
                if (delta > TimeSpan.Zero && delta <= TimeSpan.FromDays(30))
                {
                    using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "RDAP", target: DomainName) : null;
                    logger?.WriteWarningCode(RdapCodes.ExpirySoon, "Domain expires in {0} days (on {1:u})", Math.Ceiling(delta.TotalDays), exp);
                }
                else if (delta > TimeSpan.FromDays(30))
                {
                    using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "RDAP", target: DomainName) : null;
                    logger?.WriteInformationCode(RdapCodes.ExpiryFuture, "Domain expires in {0} days (on {1:u})", Math.Ceiling(delta.TotalDays), exp);
                }
            }
            else
            {
                using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "RDAP", target: DomainName) : null;
                logger?.WriteInformationCode(RdapCodes.ParseAnomaly, "RDAP parse anomaly: missing expiration event");
            }
        }
    }
}
