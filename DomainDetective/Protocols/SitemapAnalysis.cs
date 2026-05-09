using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;
using DomainDetective.Helpers;

namespace DomainDetective;

/// <summary>
/// Downloads, parses, and validates sitemap XML documents and optionally probes listed URLs.
/// </summary>
public sealed class SitemapAnalysis : IHasAssessments {
    private const string SitemapNamespace = "http://www.sitemaps.org/schemas/sitemap/0.9";
    private static readonly Lazy<XmlSchemaSet> _protocolSchemas = new(LoadProtocolSchemas);
    private static readonly XNamespace _sitemapNs = SitemapNamespace;
    private static readonly XNamespace _xhtmlNs = "http://www.w3.org/1999/xhtml";
    private static readonly HashSet<string> _imageNamespaces = new(StringComparer.OrdinalIgnoreCase) {
        "http://www.google.com/schemas/sitemap-image/1.1",
        "https://www.google.com/schemas/sitemap-image/1.1"
    };
    private static readonly HashSet<string> _newsNamespaces = new(StringComparer.OrdinalIgnoreCase) {
        "http://www.google.com/schemas/sitemap-news/0.9",
        "https://www.google.com/schemas/sitemap-news/0.9"
    };
    private static readonly HashSet<string> _videoNamespaces = new(StringComparer.OrdinalIgnoreCase) {
        "http://www.google.com/schemas/sitemap-video/1.1",
        "https://www.google.com/schemas/sitemap-video/1.1"
    };
    private static readonly HashSet<string> _validChangeFrequencies = new(StringComparer.OrdinalIgnoreCase) {
        "always",
        "hourly",
        "daily",
        "weekly",
        "monthly",
        "yearly",
        "never"
    };

    /// <summary>Subject that was analyzed.</summary>
    public string Subject { get; private set; } = string.Empty;
    /// <summary>Origin URL selected for relative sitemap discovery.</summary>
    public Uri? OriginUri { get; private set; }
    /// <summary>Sitemap URLs discovered from input, robots.txt, and conventional locations.</summary>
    public List<string> SitemapUrls { get; } = new();
    /// <summary>Sitemap XML documents fetched during analysis.</summary>
    public List<SitemapDocument> Documents { get; } = new();
    /// <summary>URL entries parsed from urlset documents.</summary>
    public List<SitemapUrlEntry> Entries { get; } = new();
    /// <summary>URL probes for parsed sitemap entries.</summary>
    public List<SitemapUrlProbe> UrlProbes { get; } = new();
    /// <summary>Structured assessments captured during the analysis.</summary>
    public List<Assessment> Assessments { get; } = new();
    /// <summary>Actionable recommendations derived from assessments.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
    /// <summary>Number of duplicate loc entries.</summary>
    public int DuplicateLocationCount { get; private set; }
    /// <summary>Number of parsed loc entries with invalid URL syntax.</summary>
    public int InvalidLocationCount { get; private set; }
    /// <summary>Number of probed URLs that redirected.</summary>
    public int RedirectCount { get; private set; }
    /// <summary>Number of probed URLs with redirect loops.</summary>
    public int RedirectLoopCount { get; private set; }
    /// <summary>Number of probed URLs returning 4xx.</summary>
    public int ClientErrorCount { get; private set; }
    /// <summary>Number of probed URLs returning 5xx.</summary>
    public int ServerErrorCount { get; private set; }
    /// <summary>Number of probed URLs marked noindex.</summary>
    public int NoIndexCount { get; private set; }
    /// <summary>Number of probed URLs whose canonical target differs from the final URL.</summary>
    public int CanonicalMismatchCount { get; private set; }
    /// <summary>Factory for HTTP message handlers; mainly useful for tests.</summary>
    public Func<HttpMessageHandler>? HttpHandlerFactory { get; set; }

    /// <summary>Executes sitemap analysis for a domain, host, sitemap URL, or HTTP/HTTPS URL.</summary>
    public async Task AnalyzeAsync(string subject, InternalLogger? logger = null, SitemapAnalysisOptions? options = null, CancellationToken cancellationToken = default) {
        if (string.IsNullOrWhiteSpace(subject)) {
            throw new ArgumentNullException(nameof(subject));
        }

        options ??= new SitemapAnalysisOptions();
        Reset(subject);

        using var client = CreateClient(options);
        var trimmedSubject = subject.Trim();
        var seeds = await DiscoverSeedSitemapsAsync(client, trimmedSubject, options, cancellationToken).ConfigureAwait(false);
        var seenDocs = new HashSet<string>(StringComparer.Ordinal);
        var seenFinalDocs = new HashSet<string>(StringComparer.Ordinal);
        await ProcessSitemapQueueAsync(client, seeds, seenDocs, seenFinalDocs, options, cancellationToken).ConfigureAwait(false);

        if (options.AllowHttpFallback &&
            IsHostSubject(trimmedSubject) &&
            !Documents.Any(document => document.Present && document.XmlValid)) {
            var fallbackSeeds = await DiscoverHttpFallbackSeedSitemapsAsync(client, trimmedSubject, options, cancellationToken).ConfigureAwait(false);
            await ProcessSitemapQueueAsync(client, fallbackSeeds, seenDocs, seenFinalDocs, options, cancellationToken).ConfigureAwait(false);
        }

        MarkDuplicateLocations();
        AddSummaryAssessments();

        if (options.ProbeUrls) {
            await ProbeSitemapUrlsAsync(client, options, cancellationToken).ConfigureAwait(false);
        }

        logger?.WriteVerbose("Sitemap analysis completed for {0}: {1} document(s), {2} URL entries, {3} probe(s)", Subject, Documents.Count, Entries.Count, UrlProbes.Count);
    }

    private async Task ProcessSitemapQueueAsync(HttpClient client, IEnumerable<Uri> seeds, HashSet<string> seenDocs, HashSet<string> seenFinalDocs, SitemapAnalysisOptions options, CancellationToken cancellationToken) {
        var pending = new Queue<Uri>(seeds);

        while (pending.Count > 0 && Documents.Count < Math.Max(1, options.MaxSitemapDocuments)) {
            cancellationToken.ThrowIfCancellationRequested();
            var sitemapUri = pending.Dequeue();
            if (!seenDocs.Add(sitemapUri.AbsoluteUri)) {
                continue;
            }

            var parsed = await FetchAndParseSitemapAsync(client, sitemapUri, seenFinalDocs, options, cancellationToken).ConfigureAwait(false);
            if (parsed.Document != null) {
                Documents.Add(parsed.Document);
            }

            foreach (var nested in parsed.NestedSitemaps) {
                if (Documents.Count + pending.Count >= Math.Max(1, options.MaxSitemapDocuments)) {
                    AddAssessment(AssessmentSeverity.Warning, SitemapCodes.LimitReached, "Sitemap document limit reached before all sitemapindex entries were fetched.", sitemapUri.AbsoluteUri);
                    break;
                }
                if (!IsTrustedRemoteUri(nested, options)) {
                    AddAssessment(AssessmentSeverity.Warning, SitemapCodes.CrossHostSitemap, "Skipped sitemap index entry outside the analyzed origin host: " + nested.Host + ".", nested.AbsoluteUri);
                    continue;
                }
                pending.Enqueue(nested);
            }

            if (Entries.Count >= Math.Max(1, options.MaxEntries)) {
                AddAssessment(AssessmentSeverity.Warning, SitemapCodes.LimitReached, "Sitemap URL entry limit reached before all urlset entries were parsed.", sitemapUri.AbsoluteUri);
                break;
            }
        }
    }

    private void Reset(string subject) {
        Subject = subject.Trim();
        OriginUri = null;
        SitemapUrls.Clear();
        Documents.Clear();
        Entries.Clear();
        UrlProbes.Clear();
        Assessments.Clear();
        DuplicateLocationCount = 0;
        InvalidLocationCount = 0;
        RedirectCount = 0;
        RedirectLoopCount = 0;
        ClientErrorCount = 0;
        ServerErrorCount = 0;
        NoIndexCount = 0;
        CanonicalMismatchCount = 0;
    }

    private HttpClient CreateClient(SitemapAnalysisOptions options) {
        HttpMessageHandler handler = HttpHandlerFactory != null
            ? HttpHandlerFactory()
            : new HttpClientHandler { AllowAutoRedirect = false };
        var client = new HttpClient(handler) {
            Timeout = options.Timeout
        };
        if (!string.IsNullOrWhiteSpace(options.UserAgent)) {
            client.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent);
        }
        return client;
    }

    private async Task<List<Uri>> DiscoverSeedSitemapsAsync(HttpClient client, string subject, SitemapAnalysisOptions options, CancellationToken cancellationToken) {
        var seeds = new List<Uri>();
        if (Uri.TryCreate(subject, UriKind.Absolute, out var absolute) &&
            (absolute.Scheme == Uri.UriSchemeHttp || absolute.Scheme == Uri.UriSchemeHttps)) {
            OriginUri = GetOrigin(absolute);
            if (absolute.AbsolutePath.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) ||
                absolute.AbsolutePath.EndsWith(".xml.gz", StringComparison.OrdinalIgnoreCase)) {
                AddSeed(seeds, absolute);
                return seeds;
            }

            await AddRobotsSitemapsAsync(client, OriginUri, seeds, options, cancellationToken).ConfigureAwait(false);
            AddSeed(seeds, new Uri(OriginUri, "/sitemap.xml"));
            return seeds;
        }

        var host = subject.Trim().TrimEnd('/');
        var origin = new Uri("https://" + host + "/");
        OriginUri ??= origin;
        await AddRobotsSitemapsAsync(client, origin, seeds, options, cancellationToken).ConfigureAwait(false);
        AddSeed(seeds, new Uri(origin, "/sitemap.xml"));

        return seeds;
    }

    private async Task<List<Uri>> DiscoverHttpFallbackSeedSitemapsAsync(HttpClient client, string subject, SitemapAnalysisOptions options, CancellationToken cancellationToken) {
        var seeds = new List<Uri>();
        var host = subject.Trim().TrimEnd('/');
        var origin = new Uri("http://" + host + "/");
        OriginUri ??= origin;
        await AddRobotsSitemapsAsync(client, origin, seeds, options, cancellationToken).ConfigureAwait(false);
        AddSeed(seeds, new Uri(origin, "/sitemap.xml"));
        return seeds;
    }

    private async Task AddRobotsSitemapsAsync(HttpClient client, Uri origin, List<Uri> seeds, SitemapAnalysisOptions options, CancellationToken cancellationToken) {
        var robotsUri = new Uri(origin, "/robots.txt");
        var response = await SendFollowingRedirectsAsync(client, robotsUri, options, readBody: true, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode < 200 || response.StatusCode >= 300 || string.IsNullOrWhiteSpace(response.Body)) {
            return;
        }

        var robots = RobotsTxtParser.Parse(response.Body!);
        foreach (var sitemap in robots.Sitemaps) {
            if (Uri.TryCreate(origin, sitemap, out var uri)) {
                if (!IsTrustedRemoteUri(uri, options)) {
                    AddAssessment(AssessmentSeverity.Warning, SitemapCodes.CrossHostSitemap, "Skipped robots.txt sitemap outside the analyzed origin host: " + uri.Host + ".", uri.AbsoluteUri);
                    continue;
                }
                AddSeed(seeds, uri);
            }
        }
    }

    private void AddSeed(List<Uri> seeds, Uri uri) {
        if (seeds.Any(existing => string.Equals(existing.AbsoluteUri, uri.AbsoluteUri, StringComparison.Ordinal))) {
            return;
        }
        seeds.Add(uri);
        if (!SitemapUrls.Contains(uri.AbsoluteUri, StringComparer.Ordinal)) {
            SitemapUrls.Add(uri.AbsoluteUri);
        }
    }

    private async Task<SitemapParseResult> FetchAndParseSitemapAsync(HttpClient client, Uri sitemapUri, HashSet<string> seenFinalDocs, SitemapAnalysisOptions options, CancellationToken cancellationToken) {
        var result = new SitemapParseResult();
        var docInfo = new SitemapDocument {
            Url = sitemapUri.AbsoluteUri
        };

        AddCrossHostSitemapAssessment(sitemapUri);

        var response = await SendFollowingRedirectsAsync(
            client,
            sitemapUri,
            options,
            readBody: true,
            cancellationToken,
            Math.Max(1024, options.MaxSitemapBodyCharacters)).ConfigureAwait(false);
        docInfo.StatusCode = response.StatusCode;
        docInfo.ContentType = response.ContentType;
        var finalUri = response.FinalUri ?? sitemapUri;
        if (!seenFinalDocs.Add(finalUri.AbsoluteUri)) {
            return result;
        }

        if (!string.IsNullOrWhiteSpace(response.Error)) {
            docInfo.Error = response.Error ?? "Sitemap download failed.";
            result.Document = docInfo;
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.DownloadFailed, docInfo.Error, sitemapUri.AbsoluteUri);
            return result;
        }

        docInfo.Present = response.StatusCode >= 200 && response.StatusCode < 300;
        if (!docInfo.Present) {
            docInfo.Error = response.Error ?? "Sitemap fetch did not return 2xx.";
            result.Document = docInfo;
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.DownloadFailed, docInfo.Error, sitemapUri.AbsoluteUri);
            return result;
        }

        AddAssessment(AssessmentSeverity.Info, SitemapCodes.Available, "Sitemap document available.", sitemapUri.AbsoluteUri);

        if (string.IsNullOrWhiteSpace(response.Body)) {
            docInfo.Error = "Sitemap response body was empty.";
            result.Document = docInfo;
            AddAssessment(AssessmentSeverity.Error, SitemapCodes.XmlInvalid, docInfo.Error, sitemapUri.AbsoluteUri);
            return result;
        }

        XDocument xml;
        try {
            xml = LoadXml(response.Body!, Math.Max(1024, options.MaxSitemapBodyCharacters));
            docInfo.XmlValid = true;
            AddAssessment(AssessmentSeverity.Info, SitemapCodes.XmlValid, "Sitemap XML is well formed.", sitemapUri.AbsoluteUri);
        } catch (Exception ex) {
            docInfo.Error = ex.Message;
            result.Document = docInfo;
            AddAssessment(AssessmentSeverity.Error, SitemapCodes.XmlInvalid, "Sitemap XML is invalid: " + ex.Message, sitemapUri.AbsoluteUri);
            return result;
        }

        var root = xml.Root;
        if (root == null) {
            docInfo.Error = "Sitemap XML has no root element.";
            result.Document = docInfo;
            AddAssessment(AssessmentSeverity.Error, SitemapCodes.RootInvalid, docInfo.Error, sitemapUri.AbsoluteUri);
            return result;
        }

        docInfo.NamespaceValid = root.Name.NamespaceName.Equals(SitemapNamespace, StringComparison.OrdinalIgnoreCase);
        if (!docInfo.NamespaceValid) {
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.NamespaceInvalid, "Sitemap root namespace is not the standard sitemap namespace.", sitemapUri.AbsoluteUri);
        }

        var schemaErrors = ValidateProtocolSchema(response.Body!, Math.Max(1024, options.MaxSitemapBodyCharacters));
        docInfo.SchemaValidationErrorCount = schemaErrors.Count;
        if (schemaErrors.Count == 0) {
            docInfo.SchemaValid = true;
            AddAssessment(AssessmentSeverity.Info, SitemapCodes.SchemaValid, "Sitemap XML matches the official Sitemap protocol schema.", sitemapUri.AbsoluteUri);
        } else {
            docInfo.SchemaValidationError = schemaErrors[0];
            AddAssessment(
                AssessmentSeverity.Error,
                SitemapCodes.SchemaInvalid,
                "Sitemap XML does not match the official Sitemap protocol schema: " + schemaErrors[0] + " (" + schemaErrors.Count.ToString(CultureInfo.InvariantCulture) + " validation error(s)).",
                sitemapUri.AbsoluteUri);
        }

        if (root.Name.LocalName.Equals("urlset", StringComparison.OrdinalIgnoreCase)) {
            docInfo.Kind = SitemapDocumentKind.UrlSet;
            ParseUrlSet(root, sitemapUri, docInfo, options);
            AddGoogleExtensionAssessments(docInfo, sitemapUri);
            if (docInfo.XhtmlAlternateLinkCount > 0) {
                AddAssessment(
                    AssessmentSeverity.Warning,
                    SitemapCodes.XhtmlAlternateExtension,
                    "Sitemap contains " + docInfo.XhtmlAlternateLinkCount.ToString(CultureInfo.InvariantCulture) + " xhtml:link alternate entries. Google supports hreflang sitemap extensions, but the base sitemaps.org schema and Chrome XML tree rendering may not treat this as a plain sitemap.",
                    sitemapUri.AbsoluteUri);
            }
        } else if (root.Name.LocalName.Equals("sitemapindex", StringComparison.OrdinalIgnoreCase)) {
            docInfo.Kind = SitemapDocumentKind.SitemapIndex;
            ParseSitemapIndex(root, sitemapUri, docInfo, result.NestedSitemaps);
        } else {
            docInfo.Kind = SitemapDocumentKind.Unknown;
            AddAssessment(AssessmentSeverity.Error, SitemapCodes.RootInvalid, "Sitemap root must be urlset or sitemapindex.", sitemapUri.AbsoluteUri);
        }

        result.Document = docInfo;
        return result;
    }

    private static XDocument LoadXml(string body, int maxCharactersInDocument) {
        var settings = new XmlReaderSettings {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = maxCharactersInDocument
        };
        using var reader = new StringReader(body.TrimStart('\uFEFF'));
        using var xmlReader = XmlReader.Create(reader, settings);
        return XDocument.Load(xmlReader, LoadOptions.None);
    }

    private static List<string> ValidateProtocolSchema(string body, int maxCharactersInDocument) {
        var errors = new List<string>();
        var settings = new XmlReaderSettings {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = maxCharactersInDocument,
            ValidationType = ValidationType.Schema,
            Schemas = _protocolSchemas.Value
        };
        settings.ValidationEventHandler += (_, e) => errors.Add(e.Message);

        try {
            using var reader = new StringReader(body.TrimStart('\uFEFF'));
            using var xmlReader = XmlReader.Create(reader, settings);
            while (xmlReader.Read()) {
                // Reading the full document drives XmlReader schema validation events.
            }
        } catch (XmlException ex) {
            errors.Add(ex.Message);
        }

        return errors;
    }

    private static XmlSchemaSet LoadProtocolSchemas() {
        var schemas = new XmlSchemaSet();
        AddProtocolSchema(schemas, "DomainDetective.Definitions.SitemapProtocol_0_9.xsd");
        AddProtocolSchema(schemas, "DomainDetective.Definitions.SitemapIndexProtocol_0_9.xsd");
        schemas.Compile();
        return schemas;
    }

    private static void AddProtocolSchema(XmlSchemaSet schemas, string resourceName) {
        var assembly = typeof(SitemapAnalysis).Assembly;
        using var stream = assembly.GetManifestResourceStream(resourceName) ??
            throw new InvalidOperationException("Schema resource '" + resourceName + "' not found.");
        using var reader = XmlReader.Create(stream);
        schemas.Add(SitemapNamespace, reader);
    }

    private void ParseUrlSet(XElement root, Uri sitemapUri, SitemapDocument docInfo, SitemapAnalysisOptions options) {
        foreach (var urlElement in ElementsByLocalName(root, "url")) {
            if (Entries.Count >= Math.Max(1, options.MaxEntries)) {
                break;
            }

            var loc = ElementValue(urlElement, "loc");
            if (string.IsNullOrWhiteSpace(loc)) {
                AddAssessment(AssessmentSeverity.Error, SitemapCodes.LocMissing, "Sitemap url entry is missing loc.", sitemapUri.AbsoluteUri);
                continue;
            }

            var locValue = loc!;
            var entry = new SitemapUrlEntry {
                SitemapUrl = sitemapUri.AbsoluteUri,
                Location = locValue,
                LastModified = ElementValue(urlElement, "lastmod"),
                ChangeFrequency = ElementValue(urlElement, "changefreq"),
                Priority = ElementValue(urlElement, "priority")
            };

            entry.LocationValid = Uri.TryCreate(locValue, UriKind.Absolute, out var locUri) &&
                                  (locUri.Scheme == Uri.UriSchemeHttp || locUri.Scheme == Uri.UriSchemeHttps);
            if (!entry.LocationValid) {
                InvalidLocationCount++;
                AddAssessment(AssessmentSeverity.Error, SitemapCodes.LocInvalid, "Sitemap loc is not an absolute HTTP/HTTPS URL: " + locValue, sitemapUri.AbsoluteUri);
            }

            if (!string.IsNullOrWhiteSpace(entry.LastModified) &&
                !DateTimeOffset.TryParse(entry.LastModified, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out _)) {
                entry.LastModifiedValid = false;
                AddAssessment(AssessmentSeverity.Warning, SitemapCodes.LastModInvalid, "Sitemap lastmod value is invalid: " + entry.LastModified, locValue);
            }

            if (!string.IsNullOrWhiteSpace(entry.ChangeFrequency) &&
                !_validChangeFrequencies.Contains(entry.ChangeFrequency!)) {
                entry.ChangeFrequencyValid = false;
                AddAssessment(AssessmentSeverity.Warning, SitemapCodes.ChangeFrequencyInvalid, "Sitemap changefreq value is invalid: " + entry.ChangeFrequency, locValue);
            }

            if (!string.IsNullOrWhiteSpace(entry.Priority)) {
                if (!decimal.TryParse(entry.Priority, NumberStyles.Number, CultureInfo.InvariantCulture, out var priority) ||
                    priority < 0 ||
                    priority > 1) {
                    entry.PriorityValid = false;
                    AddAssessment(AssessmentSeverity.Warning, SitemapCodes.PriorityInvalid, "Sitemap priority must be between 0.0 and 1.0: " + entry.Priority, locValue);
                }
            }

            foreach (var alternate in urlElement.Elements(_xhtmlNs + "link")) {
                entry.Alternates.Add(new SitemapAlternateLink {
                    Rel = (string?)alternate.Attribute("rel"),
                    HrefLang = (string?)alternate.Attribute("hreflang"),
                    Href = (string?)alternate.Attribute("href")
                });
            }

            docInfo.XhtmlAlternateLinkCount += entry.Alternates.Count;
            RecordGoogleExtensionCounts(urlElement, docInfo);
            Entries.Add(entry);
            docInfo.UrlCount++;
        }
    }

    private static void RecordGoogleExtensionCounts(XElement urlElement, SitemapDocument docInfo) {
        foreach (var element in urlElement.Descendants()) {
            if (IsGoogleExtensionElement(element, "image", _imageNamespaces)) {
                docInfo.ImageExtensionElementCount++;
            } else if (IsGoogleExtensionElement(element, "news", _newsNamespaces)) {
                docInfo.NewsExtensionElementCount++;
            } else if (IsGoogleExtensionElement(element, "video", _videoNamespaces)) {
                docInfo.VideoExtensionElementCount++;
            }
        }
    }

    private static bool IsGoogleExtensionElement(XElement element, string localName, HashSet<string> namespaces) {
        return element.Name.LocalName.Equals(localName, StringComparison.OrdinalIgnoreCase) &&
               namespaces.Contains(element.Name.NamespaceName);
    }

    private void AddGoogleExtensionAssessments(SitemapDocument docInfo, Uri sitemapUri) {
        if (docInfo.ImageExtensionElementCount > 0) {
            AddAssessment(
                AssessmentSeverity.Warning,
                SitemapCodes.ImageExtension,
                "Sitemap contains " + docInfo.ImageExtensionElementCount.ToString(CultureInfo.InvariantCulture) + " Google image sitemap extension element(s). Strict base sitemap schema validation may report these separately from Google crawler support.",
                sitemapUri.AbsoluteUri);
        }

        if (docInfo.NewsExtensionElementCount > 0) {
            AddAssessment(
                AssessmentSeverity.Warning,
                SitemapCodes.NewsExtension,
                "Sitemap contains " + docInfo.NewsExtensionElementCount.ToString(CultureInfo.InvariantCulture) + " Google News sitemap extension element(s). Strict base sitemap schema validation may report these separately from Google crawler support.",
                sitemapUri.AbsoluteUri);
        }

        if (docInfo.VideoExtensionElementCount > 0) {
            AddAssessment(
                AssessmentSeverity.Warning,
                SitemapCodes.VideoExtension,
                "Sitemap contains " + docInfo.VideoExtensionElementCount.ToString(CultureInfo.InvariantCulture) + " Google video sitemap extension element(s). Strict base sitemap schema validation may report these separately from Google crawler support.",
                sitemapUri.AbsoluteUri);
        }
    }

    private void ParseSitemapIndex(XElement root, Uri sitemapUri, SitemapDocument docInfo, List<Uri> nestedSitemaps) {
        AddAssessment(AssessmentSeverity.Info, SitemapCodes.SitemapIndexPresent, "Sitemap index found.", sitemapUri.AbsoluteUri);
        foreach (var sitemapElement in ElementsByLocalName(root, "sitemap")) {
            var loc = ElementValue(sitemapElement, "loc");
            if (string.IsNullOrWhiteSpace(loc)) {
                AddAssessment(AssessmentSeverity.Error, SitemapCodes.LocMissing, "Sitemap index entry is missing loc.", sitemapUri.AbsoluteUri);
                continue;
            }

            if (Uri.TryCreate(sitemapUri, loc, out var uri) &&
                (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps)) {
                nestedSitemaps.Add(uri);
                docInfo.SitemapCount++;
            } else {
                AddAssessment(AssessmentSeverity.Error, SitemapCodes.LocInvalid, "Sitemap index loc is not a valid HTTP/HTTPS URL: " + loc, sitemapUri.AbsoluteUri);
            }
        }
    }

    private static IEnumerable<XElement> ElementsByLocalName(XElement element, string localName) {
        return element.Elements().Where(child => child.Name.LocalName.Equals(localName, StringComparison.OrdinalIgnoreCase));
    }

    private static string? ElementValue(XElement element, string localName) {
        return ElementsByLocalName(element, localName).FirstOrDefault()?.Value.Trim();
    }

    private void MarkDuplicateLocations() {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in Entries) {
            if (!entry.LocationValid) {
                continue;
            }

            if (!seen.Add(entry.Location)) {
                entry.Duplicate = true;
                DuplicateLocationCount++;
                AddAssessment(AssessmentSeverity.Warning, SitemapCodes.LocDuplicate, "Duplicate sitemap loc entry: " + entry.Location, entry.Location);
            }
        }
    }

    private void AddSummaryAssessments() {
        if (Documents.Count == 0) {
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.Missing, "No sitemap document was found.", Subject);
            return;
        }

        if (Entries.Count > 0) {
            AddAssessment(AssessmentSeverity.Info, SitemapCodes.UrlEntryPresent, Entries.Count.ToString(CultureInfo.InvariantCulture) + " sitemap URL entries parsed.", Subject);
        }
    }

    private async Task ProbeSitemapUrlsAsync(HttpClient client, SitemapAnalysisOptions options, CancellationToken cancellationToken) {
        var probeLimit = Math.Max(0, Math.Min(options.MaxUrlProbes, Entries.Count));
        if (Entries.Count > probeLimit) {
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.LimitReached, "URL probe limit reached; checked " + probeLimit.ToString(CultureInfo.InvariantCulture) + " of " + Entries.Count.ToString(CultureInfo.InvariantCulture) + " sitemap entries.", Subject);
        }

        foreach (var entry in Entries.Where(entry => entry.LocationValid).Take(probeLimit)) {
            cancellationToken.ThrowIfCancellationRequested();
            if (options.RestrictRemoteFetchesToOriginHost &&
                Uri.TryCreate(entry.Location, UriKind.Absolute, out var entryUri) &&
                !IsTrustedRemoteUri(entryUri, options)) {
                AddAssessment(AssessmentSeverity.Warning, SitemapCodes.UrlFetchFailed, "Skipped sitemap URL probe outside the analyzed origin host.", entry.Location);
                continue;
            }

            var probe = await ProbeUrlAsync(client, entry.Location, options, cancellationToken).ConfigureAwait(false);
            UrlProbes.Add(probe);
            AddProbeAssessment(probe);
        }
    }

    private async Task<SitemapUrlProbe> ProbeUrlAsync(HttpClient client, string url, SitemapAnalysisOptions options, CancellationToken cancellationToken) {
        var probe = new SitemapUrlProbe {
            Url = url
        };

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) {
            probe.Error = "Invalid URL.";
            return probe;
        }

        var response = await SendFollowingRedirectsAsync(client, uri, options, readBody: options.CheckCanonical, cancellationToken).ConfigureAwait(false);
        probe.StatusCode = response.StatusCode;
        probe.ContentType = response.ContentType;
        probe.FinalUrl = response.FinalUri?.AbsoluteUri;
        probe.Error = response.Error;
        probe.WasRedirected = response.WasRedirected;
        probe.RedirectLoop = response.RedirectLoop;
        probe.RedirectHopCount = response.RedirectChain.Count > 0 ? Math.Max(0, response.RedirectChain.Count - 1) : 0;
        foreach (var item in response.RedirectChain) {
            probe.RedirectChain.Add(item);
        }

        var status = response.StatusCode ?? 0;
        probe.Success = status >= 200 && status < 300 && !probe.RedirectLoop;
        if (probe.Success && options.CheckCanonical) {
            probe.NoIndex = HasNoIndex(response.Headers, response.Body);
            probe.CanonicalUrl = ExtractCanonical(response.FinalUri ?? uri, response.Body);
            if (!string.IsNullOrWhiteSpace(probe.CanonicalUrl) && response.FinalUri != null) {
                probe.CanonicalMismatch = !UrlsEqualWithoutFragment(probe.CanonicalUrl!, response.FinalUri.AbsoluteUri);
            }
        }

        return probe;
    }

    private void AddProbeAssessment(SitemapUrlProbe probe) {
        if (probe.RedirectLoop) {
            RedirectLoopCount++;
            AddAssessment(AssessmentSeverity.Error, SitemapCodes.UrlRedirectLoop, "Sitemap URL has a redirect loop.", probe.Url);
            return;
        }

        if (!probe.StatusCode.HasValue || probe.StatusCode.Value == 0) {
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.UrlFetchFailed, probe.Error ?? "Sitemap URL fetch failed.", probe.Url);
            return;
        }

        if (probe.StatusCode.Value >= 300 && probe.StatusCode.Value < 400) {
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.UrlFetchFailed, probe.Error ?? "Sitemap URL redirect could not be followed.", probe.Url);
            return;
        }

        if (probe.StatusCode.Value >= 500) {
            ServerErrorCount++;
            AddAssessment(AssessmentSeverity.Error, SitemapCodes.UrlServerError, "Sitemap URL returned HTTP " + probe.StatusCode.Value.ToString(CultureInfo.InvariantCulture) + ".", probe.Url);
        } else if (probe.StatusCode.Value == 401 || probe.StatusCode.Value == 403) {
            ClientErrorCount++;
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.UrlAccessForbidden, "Sitemap URL returned HTTP " + probe.StatusCode.Value.ToString(CultureInfo.InvariantCulture) + " to the unauthenticated probe. The page may still exist for browser sessions.", probe.Url);
        } else if (probe.StatusCode.Value >= 400) {
            ClientErrorCount++;
            AddAssessment(AssessmentSeverity.Error, SitemapCodes.UrlClientError, "Sitemap URL returned HTTP " + probe.StatusCode.Value.ToString(CultureInfo.InvariantCulture) + ".", probe.Url);
        } else if (probe.WasRedirected) {
            RedirectCount++;
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.UrlRedirect, "Sitemap URL redirects to " + (probe.FinalUrl ?? "another URL") + ".", probe.Url);
        } else {
            AddAssessment(AssessmentSeverity.Info, SitemapCodes.UrlOk, "Sitemap URL returned a successful response.", probe.Url);
        }

        if (probe.NoIndex) {
            NoIndexCount++;
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.UrlNoIndex, "Sitemap URL is marked noindex.", probe.Url);
        }

        if (probe.CanonicalMismatch) {
            CanonicalMismatchCount++;
            AddAssessment(AssessmentSeverity.Warning, SitemapCodes.CanonicalMismatch, "Sitemap URL canonicalizes to " + probe.CanonicalUrl + ".", probe.Url);
        }
    }

    private async Task<SitemapHttpResult> SendFollowingRedirectsAsync(HttpClient client, Uri startUri, SitemapAnalysisOptions options, bool readBody, CancellationToken cancellationToken, int? maxBodyCharacters = null) {
        var result = new SitemapHttpResult();
        var current = startUri;
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i <= Math.Max(0, options.MaxRedirects); i++) {
            cancellationToken.ThrowIfCancellationRequested();
            result.RedirectChain.Add(current.AbsoluteUri);
            if (!visited.Add(current.AbsoluteUri)) {
                result.RedirectLoop = true;
                result.FinalUri = current;
                result.Error = "Redirect loop detected.";
                return result;
            }

            HttpResponseMessage response;
            try {
                using var request = new HttpRequestMessage(HttpMethod.Get, current);
                response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            } catch (Exception ex) {
                result.FinalUri = current;
                result.Error = ex.Message;
                return result;
            }

            using (response) {
                result.StatusCode = (int)response.StatusCode;
                result.ContentType = response.Content?.Headers?.ContentType?.MediaType ?? response.Content?.Headers?.ContentType?.ToString();
                result.Headers = CaptureHeaders(response);

                if (IsRedirect(response.StatusCode)) {
                    if (response.Headers.Location == null) {
                        result.FinalUri = current;
                        result.Error = "Redirect response did not include Location.";
                        return result;
                    }

                    var next = response.Headers.Location.IsAbsoluteUri
                        ? response.Headers.Location
                        : new Uri(current, response.Headers.Location);
                    if (!IsTrustedRemoteUri(next, options)) {
                        result.FinalUri = current;
                        result.Error = "Redirect target is outside the analyzed origin host.";
                        return result;
                    }

                    result.WasRedirected = true;
                    current = next;
                    continue;
                }

                result.FinalUri = current;
                if (readBody && response.Content != null) {
                    var shouldDecompressGzip = HasGzipHeader(response.Content);
                    try {
                        result.Body = await ReadLimitedBodyAsync(response.Content, maxBodyCharacters ?? 262144, shouldDecompressGzip, cancellationToken).ConfigureAwait(false);
                        if ((shouldDecompressGzip || current.AbsolutePath.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) && string.IsNullOrEmpty(result.Body)) {
                            result.Error = "Sitemap response gzip body could not be decompressed or was empty.";
                        }
                    } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                        throw;
                    } catch (InvalidDataException ex) {
                        result.Error = "Sitemap response gzip body could not be decompressed: " + ex.Message;
                    } catch (Exception ex) when (ex is IOException || ex is HttpRequestException) {
                        result.Error = "Sitemap response body could not be read: " + ex.Message;
                    }
                }
                return result;
            }
        }

        result.FinalUri = current;
        result.RedirectLoop = true;
        result.Error = "Maximum redirects exceeded.";
        return result;
    }

    private static bool IsRedirect(HttpStatusCode statusCode) {
        var code = (int)statusCode;
        return code >= 300 && code < 400;
    }

    private static Dictionary<string, string> CaptureHeaders(HttpResponseMessage response) {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in response.Headers) {
            headers[header.Key] = string.Join(",", header.Value);
        }
        if (response.Content != null) {
            foreach (var header in response.Content.Headers) {
                headers[header.Key] = string.Join(",", header.Value);
            }
        }
        return headers;
    }

    private static async Task<string?> ReadLimitedBodyAsync(HttpContent content, int maxCharacters, bool decompressGzip, CancellationToken cancellationToken) {
        var limit = Math.Max(1024, maxCharacters);

        Encoding encoding;
        try {
            var charset = content.Headers.ContentType?.CharSet;
            var trimmedCharset = string.Empty;
            if (!string.IsNullOrWhiteSpace(charset)) {
                trimmedCharset = charset!.Trim('"');
            }

            encoding = string.IsNullOrWhiteSpace(trimmedCharset)
                ? Encoding.UTF8
                : Encoding.GetEncoding(trimmedCharset);
        } catch (ArgumentException) {
            encoding = Encoding.UTF8;
        }

        using var stream = await content.ReadAsStreamAsync().ConfigureAwait(false);
        using var readableStream = await CreateReadableBodyStreamAsync(stream, decompressGzip, cancellationToken).ConfigureAwait(false);
        using var reader = new StreamReader(readableStream, encoding, detectEncodingFromByteOrderMarks: true, bufferSize: 8192);
        var builder = new StringBuilder(Math.Min(limit, 8192));
        var buffer = new char[Math.Min(limit, 8192)];

        while (builder.Length < limit) {
            cancellationToken.ThrowIfCancellationRequested();
            var remaining = limit - builder.Length;
            var read = await reader.ReadAsync(buffer, 0, Math.Min(buffer.Length, remaining)).ConfigureAwait(false);
            if (read == 0) {
                break;
            }

            builder.Append(buffer, 0, read);
        }

        return builder.ToString();
    }

    private static async Task<Stream> CreateReadableBodyStreamAsync(Stream stream, bool decompressGzip, CancellationToken cancellationToken) {
        if (decompressGzip) {
            return new GZipStream(stream, CompressionMode.Decompress);
        }

        var prefix = new byte[2];
        var read = 0;
        while (read < prefix.Length) {
            cancellationToken.ThrowIfCancellationRequested();
            var count = await stream.ReadAsync(prefix, read, prefix.Length - read).ConfigureAwait(false);
            if (count == 0) {
                break;
            }

            read += count;
        }

        var prefixedStream = new PrefixedStream(prefix, read, stream);
        if (read >= 2 && prefix[0] == 0x1f && prefix[1] == 0x8b) {
            return new GZipStream(prefixedStream, CompressionMode.Decompress);
        }

        return prefixedStream;
    }

    private static bool HasGzipHeader(HttpContent content) {
        if (content.Headers.ContentEncoding.Any(value => value.Equals("gzip", StringComparison.OrdinalIgnoreCase))) {
            return true;
        }

        return HasGzipMediaType(content.Headers.ContentType?.MediaType);
    }

    private static bool HasGzipMediaType(string? mediaType) {
        if (string.IsNullOrWhiteSpace(mediaType)) {
            return false;
        }

        return mediaType!.IndexOf("gzip", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private sealed class PrefixedStream : Stream {
        private readonly byte[] _prefix;
        private readonly int _prefixLength;
        private readonly Stream _inner;
        private int _prefixOffset;

        public PrefixedStream(byte[] prefix, int prefixLength, Stream inner) {
            _prefix = prefix;
            _prefixLength = prefixLength;
            _inner = inner;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() {
        }

        public override int Read(byte[] buffer, int offset, int count) {
            var copied = CopyPrefix(buffer, offset, count);
            if (copied == count) {
                return copied;
            }

            return copied + _inner.Read(buffer, offset + copied, count - copied);
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) {
            var copied = CopyPrefix(buffer, offset, count);
            if (copied == count) {
                return copied;
            }

            return copied + await _inner.ReadAsync(buffer, offset + copied, count - copied, cancellationToken).ConfigureAwait(false);
        }

        public override long Seek(long offset, SeekOrigin origin) {
            throw new NotSupportedException();
        }

        public override void SetLength(long value) {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count) {
            throw new NotSupportedException();
        }

        private int CopyPrefix(byte[] buffer, int offset, int count) {
            if (_prefixOffset >= _prefixLength || count == 0) {
                return 0;
            }

            var available = _prefixLength - _prefixOffset;
            var copy = Math.Min(available, count);
            Buffer.BlockCopy(_prefix, _prefixOffset, buffer, offset, copy);
            _prefixOffset += copy;
            return copy;
        }
    }

    private static bool HasNoIndex(Dictionary<string, string> headers, string? body) {
        if (headers.TryGetValue("X-Robots-Tag", out var xRobots) &&
            xRobots.IndexOf("noindex", StringComparison.OrdinalIgnoreCase) >= 0) {
            return true;
        }

        return !string.IsNullOrWhiteSpace(body) &&
               Regex.IsMatch(body, "(?is)<meta\\s+[^>]*(?:name|property)=[\"']robots[\"'][^>]*content=[\"'][^\"']*noindex");
    }

    private static string? ExtractCanonical(Uri baseUri, string? body) {
        if (string.IsNullOrWhiteSpace(body)) {
            return null;
        }

        var match = Regex.Match(body, "(?is)<link\\s+[^>]*rel=[\"']canonical[\"'][^>]*href=[\"']([^\"']+)[\"']");
        if (!match.Success) {
            match = Regex.Match(body, "(?is)<link\\s+[^>]*href=[\"']([^\"']+)[\"'][^>]*rel=[\"']canonical[\"']");
        }

        if (!match.Success) {
            return null;
        }

        var value = WebUtility.HtmlDecode(match.Groups[1].Value);
        if (Uri.TryCreate(baseUri, value, out var canonical)) {
            return canonical.AbsoluteUri;
        }

        return value;
    }

    private static bool UrlsEqualWithoutFragment(string left, string right) {
        if (!Uri.TryCreate(left, UriKind.Absolute, out var l) ||
            !Uri.TryCreate(right, UriKind.Absolute, out var r)) {
            return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
        }

        var lb = new UriBuilder(l) { Fragment = string.Empty };
        var rb = new UriBuilder(r) { Fragment = string.Empty };
        return string.Equals(lb.Uri.AbsoluteUri.TrimEnd('/'), rb.Uri.AbsoluteUri.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);
    }

    private static Uri GetOrigin(Uri uri) {
        var builder = new UriBuilder(uri.Scheme, uri.Host, uri.IsDefaultPort ? -1 : uri.Port);
        return builder.Uri;
    }

    private static bool IsHostSubject(string subject) {
        return !Uri.TryCreate(subject, UriKind.Absolute, out var absolute) ||
               (absolute.Scheme != Uri.UriSchemeHttp && absolute.Scheme != Uri.UriSchemeHttps);
    }

    private void AddCrossHostSitemapAssessment(Uri sitemapUri) {
        if (OriginUri == null || IsSameHost(OriginUri, sitemapUri)) {
            return;
        }

        AddAssessment(
            AssessmentSeverity.Warning,
            SitemapCodes.CrossHostSitemap,
            "Sitemap document is hosted on " + sitemapUri.Host + " while the analyzed origin is " + OriginUri.Host + ".",
            sitemapUri.AbsoluteUri);
    }

    private static bool IsSameHost(Uri left, Uri right) {
        return string.Equals(NormalizeComparableHost(left.Host), NormalizeComparableHost(right.Host), StringComparison.OrdinalIgnoreCase);
    }

    private bool IsTrustedRemoteUri(Uri uri, SitemapAnalysisOptions options) {
        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) {
            return false;
        }

        if (!options.RestrictRemoteFetchesToOriginHost || OriginUri == null) {
            return true;
        }

        return IsSameHost(OriginUri, uri);
    }

    private static string NormalizeComparableHost(string host) {
        var normalized = host.TrimEnd('.');
        if (normalized.StartsWith("www.", StringComparison.OrdinalIgnoreCase)) {
            return normalized.Substring(4);
        }

        return normalized;
    }

    private void AddAssessment(AssessmentSeverity severity, string code, string message, string? target) {
        Assessments.Add(new Assessment {
            Severity = severity,
            Category = "Sitemap",
            Target = target ?? Subject,
            Code = code,
            Message = message
        });
    }

    private sealed class SitemapParseResult {
        public SitemapDocument? Document { get; set; }
        public List<Uri> NestedSitemaps { get; } = new();
    }

    private sealed class SitemapHttpResult {
        public int? StatusCode { get; set; }
        public string? ContentType { get; set; }
        public Uri? FinalUri { get; set; }
        public string? Body { get; set; }
        public string? Error { get; set; }
        public bool WasRedirected { get; set; }
        public bool RedirectLoop { get; set; }
        public Dictionary<string, string> Headers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> RedirectChain { get; } = new();
    }
}
