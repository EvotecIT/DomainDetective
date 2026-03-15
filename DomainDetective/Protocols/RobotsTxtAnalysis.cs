using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective;

/// <summary>
/// Downloads and parses robots.txt files.
/// </summary>
public class RobotsTxtAnalysis : IHasAssessments
{
    private record CacheEntry(string Content, string Url, bool Fallback, DateTimeOffset Expires);
    private static readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Maximum time cached results are kept.</summary>
    public TimeSpan CacheDuration { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Domain that was analyzed.</summary>
    public string Domain { get; private set; } = string.Empty;

    /// <summary>True when a robots.txt file was found.</summary>
    public bool RecordPresent { get; private set; }

    /// <summary>Indicates a fallback to HTTP was used.</summary>
    public bool FallbackUsed { get; private set; }

    /// <summary>URL the robots.txt was downloaded from.</summary>
    public string? Url { get; private set; }

    /// <summary>Parsed robots.txt data.</summary>
    public RobotsFile? Robots { get; private set; }

    /// <summary>List of AI user-agents found in the file grouped by bot type.</summary>
    public Dictionary<KnownAiBot, List<string>> AiBots { get; } = new();

    /// <summary>Indicates whether AI bot directives are present.</summary>
    public bool HasAiBotRules => AiBots.Count > 0;

    internal InternalLogger? Logger { get; set; }
    public List<Assessment> Assessments { get; } = new();

    private static readonly HttpClient _client;

    static RobotsTxtAnalysis()
    {
        _client = HttpClientPlatformFactory.CreateRedirectClient(userAgent: "Mozilla/5.0 (compatible; DomainDetective)");
    }

    /// <summary>Clears the shared cache.</summary>
    public static void ClearCache() => _cache.Clear();

    /// <summary>
    /// Retrieves and parses robots.txt for <paramref name="domain"/>.
    /// </summary>
    public async Task AnalyzeAsync(string domain, InternalLogger? logger = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentNullException(nameof(domain));
        }
        if (!Uri.TryCreate($"http://{domain}", UriKind.Absolute, out _))
        {
            throw new ArgumentException("Invalid host name.", nameof(domain));
        }

        Logger = logger;
        Domain = domain;
        RecordPresent = false;
        Robots = null;
        AiBots.Clear();

        if (_cache.TryGetValue(domain, out var cached) && cached.Expires > DateTimeOffset.UtcNow)
        {
            RecordPresent = true;
            FallbackUsed = cached.Fallback;
            Url = cached.Url;
            Robots = RobotsTxtParser.Parse(cached.Content);
            DetectAiBots();
            if (HasAiBotRules)
            {
                Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Info,
                    Category = "Robots",
                    Target = Domain,
                    Code = RobotsTxtCodes.AiBotDirectivesPresent,
                    Message = "AI bot directives present in robots.txt"
                });
            }
            return;
        }

        string url = $"https://{domain}/robots.txt";
        string? content = await GetRobotsTxt(url, cancellationToken).ConfigureAwait(false);
        bool fallback = false;

        if (content == null)
        {
            url = $"http://{domain}/robots.txt";
            content = await GetRobotsTxt(url, cancellationToken).ConfigureAwait(false);
            fallback = true;
        }

        if (content != null)
        {
            RecordPresent = true;
            FallbackUsed = fallback;
            Url = url;
            Robots = RobotsTxtParser.Parse(content);
            DetectAiBots();
            _cache[domain] = new CacheEntry(content, url, fallback, DateTimeOffset.UtcNow.Add(CacheDuration));
            if (fallback)
            {
                Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Info,
                    Category = "Robots",
                    Target = Domain,
                    Code = RobotsTxtCodes.FallbackHttp,
                    Message = "robots.txt retrieved over HTTP (no HTTPS)"
                });
            }
            else
            {
                Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Info,
                    Category = "Robots",
                    Target = Domain,
                    Code = RobotsTxtCodes.Available,
                    Message = "robots.txt available over HTTPS"
                });
            }
            if (HasAiBotRules)
            {
                Assessments.Add(new Assessment
                {
                    Severity = AssessmentSeverity.Info,
                    Category = "Robots",
                    Target = Domain,
                    Code = RobotsTxtCodes.AiBotDirectivesPresent,
                    Message = "AI bot directives present in robots.txt"
                });
            }

            var hasDisallow = Robots?.Groups.Any(g => g.Directives.Any(d => d.Type == RobotsDirectiveType.Disallow)) ?? false;
            if (hasDisallow)
            {
                Assessments.Add(new Assessment
                {
                    Severity = AssessmentSeverity.Info,
                    Category = "Robots",
                    Target = Domain,
                    Code = RobotsTxtCodes.DisallowPresent,
                    Message = "robots.txt defines disallow rules"
                });
            }

            if (Robots?.Sitemaps.Count > 0)
            {
                Assessments.Add(new Assessment
                {
                    Severity = AssessmentSeverity.Info,
                    Category = "Robots",
                    Target = Domain,
                    Code = RobotsTxtCodes.SitemapPresent,
                    Message = "robots.txt references sitemap"
                });
            }
        }
        else
        {
            Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Info,
                Category = "Robots",
                Target = Domain,
                Code = RobotsTxtCodes.Missing,
                Message = "robots.txt not found"
            });
        }
    }

    private async Task<string?> GetRobotsTxt(string url, CancellationToken token)
    {
        try
        {
            var resp = await _client.GetAsync(url, token).ConfigureAwait(false);
            if (resp.IsSuccessStatusCode)
            {
                return await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            Logger?.WriteDebug("Failed to download robots.txt from {0}: {1}", url, ex.Message);
            Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Info,
                Category = "Robots",
                Target = Domain,
                Code = RobotsTxtCodes.DownloadFailed,
                Message = $"robots.txt download failed from {url}"
            });
        }
        return null;
    }

    private void DetectAiBots()
    {
        if (Robots == null)
        {
            return;
        }

        var patterns = new Dictionary<KnownAiBot, string[]>
        {
            [KnownAiBot.GptBot] = new[] { "gptbot" },
            [KnownAiBot.ChatGpt] = new[] { "chatgpt" },
            [KnownAiBot.ChatGptUser] = new[] { "chatgpt-user" },
            [KnownAiBot.CcBot] = new[] { "ccbot" },
            [KnownAiBot.ClaudeBot] = new[] { "claudebot" },
            [KnownAiBot.Anthropic] = new[] { "anthropic" },
            [KnownAiBot.GoogleExtended] = new[] { "google-extended" }
        };

        foreach (var group in Robots.Groups)
        {
            foreach (var agent in group.UserAgents)
            {
                var found = KnownAiBot.Unknown;

                foreach (var kvp in patterns)
                {
                    foreach (var pattern in kvp.Value)
                    {
                        if (agent.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            found = kvp.Key;
                            break;
                        }
                    }
                    if (found != KnownAiBot.Unknown)
                    {
                        break;
                    }
                }

                if (!AiBots.TryGetValue(found, out var list))
                {
                    list = new List<string>();
                    AiBots[found] = list;
                }

                if (!list.Contains(agent))
                {
                    list.Add(agent);
                }
            }
        }
    }
}
