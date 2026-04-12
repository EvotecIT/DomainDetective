using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Scans common directories on a web server looking for inadvertent exposure.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class DirectoryExposureAnalysis : IHasAssessments
{
    private static readonly string[] _defaultPaths = LoadDefaultPaths();

    private static string[] LoadDefaultPaths()
    {
        try
        {
            using var stream = Assembly.GetExecutingAssembly()
                .GetManifestResourceStream("DomainDetective.directory_paths.json");
            if (stream != null)
            {
                using var reader = new StreamReader(stream);
                var json = reader.ReadToEnd();
                var items = JsonSerializer.Deserialize<string[]>(json)
                    ?.Where(p => !string.IsNullOrWhiteSpace(p))
                    ?? Enumerable.Empty<string>();
                return items.ToArray();
            }
        }
        catch
        {
            // ignore malformed resource
        }

        return Array.Empty<string>();
    }

    /// <summary>HTTP client timeout for each request.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Subject of the check (normalized base URL).</summary>
    public string? Subject { get; set; }

    /// <summary>List of directories detected as accessible.</summary>
    public List<string> ExposedPaths { get; private set; } = new();

    /// <summary>
    /// Checks the target host for exposed directories.
    /// </summary>
    /// <param name="baseUrl">Base URL, e.g. http://example.com</param>
    /// <param name="logger">Logger for verbose output.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task Analyze(string baseUrl, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "DIR", target: baseUrl);
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            throw new ArgumentNullException(nameof(baseUrl));
        }

        if (!baseUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !baseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            baseUrl = "http://" + baseUrl.TrimEnd('/');
        }
        else
        {
            baseUrl = baseUrl.TrimEnd('/');
        }

        Subject = baseUrl;

        ExposedPaths.Clear();

        using var client = new HttpClient { Timeout = Timeout };
        foreach (var path in _defaultPaths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var url = $"{baseUrl}/{path}";
            try
            {
                var response = await client.GetAsync(url, cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    ExposedPaths.Add(path);
                    var p = (path ?? string.Empty);
                    var pNorm = p.Trim('/');
                    var isDir = p.EndsWith("/");
                    var isEnv = pNorm.Equals(".env", StringComparison.OrdinalIgnoreCase);
                    var isBackup = isDir && ((pNorm.IndexOf("backup", StringComparison.OrdinalIgnoreCase) >= 0) || pNorm.StartsWith("_backup", StringComparison.OrdinalIgnoreCase))
                                  || pNorm.Equals(".DS_Store", StringComparison.OrdinalIgnoreCase)
                                  || pNorm.EndsWith(".bak", StringComparison.OrdinalIgnoreCase)
                                  || pNorm.EndsWith("~", StringComparison.Ordinal);
                    var isSourceMap = pNorm.EndsWith(".map", StringComparison.OrdinalIgnoreCase);
                    var isSitemap = pNorm.Equals("sitemap.xml", StringComparison.OrdinalIgnoreCase) || pNorm.Equals("sitemap.txt", StringComparison.OrdinalIgnoreCase);
                    var isSecurityTxt = pNorm.Equals(".well-known/security.txt", StringComparison.OrdinalIgnoreCase);

                    if (isEnv)
                    {
                        logger?.WriteErrorCode(DirectoryExposureCodes.SecretsDotEnv, "Exposed secret file {0}", url);
                    }
                    else if (isBackup)
                    {
                        logger?.WriteWarningCode(DirectoryExposureCodes.BackupsPresent, "Exposed backup/artifact {0}", url);
                    }
                    else if (isSourceMap)
                    {
                        logger?.WriteWarningCode(DirectoryExposureCodes.SourceMapExposed, "Exposed source map {0}", url);
                    }
                    else if (isSitemap)
                    {
                        logger?.WriteInformationCode(DirectoryExposureCodes.InfoSitemapPresent, "Sitemap present {0}", url);
                    }
                    else if (isSecurityTxt)
                    {
                        logger?.WriteInformationCode(DirectoryExposureCodes.InfoSecurityTxtPresent, "security.txt present {0}", url);
                    }
                    else if (isDir)
                    {
                        logger?.WriteWarningCode(DirectoryExposureCodes.ExposedDirectory, "Exposed directory {0}", url);
                    }
                    else
                    {
                        // generic exposed path (file)
                        logger?.WriteWarningCode(DirectoryExposureCodes.ExposedDirectory, "Exposed path {0}", url);
                    }
                }
            }
            catch (Exception ex) when (ex is HttpRequestException || ex is TaskCanceledException)
            {
                logger?.WriteDebug("Failed to query {0}: {1}", url, ex.Message);
            }
        }

        if (ExposedPaths.Count == 0)
        {
            logger?.WriteInformationCode(DirectoryExposureCodes.DirectoryListingDisabled, "Directory browsing disabled for common paths");
        }
    }

    /// <summary>Gets the assessments value.</summary>
    public List<Assessment> Assessments { get; } = new();
    /// <summary>Represents the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
}
