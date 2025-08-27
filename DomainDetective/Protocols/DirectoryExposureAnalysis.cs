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
                    logger?.WriteWarningCode(DirectoryExposureCodes.ExposedDirectory, "Exposed directory {0}", url);
                }
            }
            catch (Exception ex) when (ex is HttpRequestException || ex is TaskCanceledException)
            {
                logger?.WriteDebug("Failed to query {0}: {1}", url, ex.Message);
            }
        }
    }

    public List<Assessment> Assessments { get; } = new();
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
}
