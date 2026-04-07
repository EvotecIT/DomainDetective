using DomainDetective;
using DomainDetective.Views;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.FileProviders;
using System.Collections.Concurrent;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
var allowedOrigins = ResolveAllowedOrigins(builder.Configuration, builder.Environment, out var usingFallbackOrigins);

builder.Services.AddCors(options => {
    options.AddDefaultPolicy(policy => {
        policy.WithOrigins(allowedOrigins)
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});
builder.Services.AddMemoryCache();
builder.Services.AddRateLimiter(options => {
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("tool-api", httpContext => {
        var remoteIpAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(remoteIpAddress, static _ => new FixedWindowRateLimiterOptions {
            PermitLimit = 20,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            AutoReplenishment = true
        });
    });
});

var app = builder.Build();
var siteRoot = ResolveSiteRoot(app.Configuration, app.Environment);

app.UseCors();
app.UseRateLimiter();

if (usingFallbackOrigins) {
    app.Logger.LogWarning(
        "Cors:AllowedOrigins was not configured. Using default {EnvironmentName} origins.",
        builder.Environment.EnvironmentName);
}

app.MapGet("/tool-api/health", () => TypedResults.Ok(new {
    status = "ok",
    siteRootExists = siteRoot != null && Directory.Exists(siteRoot)
}));

app.MapGet("/tools/data/tools-runtime.json", () => TypedResults.Ok(new {
    mode = "HostedOnline"
}));

app.MapPost("/tool-api/http-headers", AnalyzeHttpHeadersAsync).RequireRateLimiting("tool-api");
app.MapPost("/tool-api/security-txt", AnalyzeSecurityTxtAsync).RequireRateLimiting("tool-api");
app.MapPost("/tool-api/cert-check", AnalyzeCertificateAsync).RequireRateLimiting("tool-api");
app.MapPost("/tool-api/bimi", AnalyzeBimiAsync).RequireRateLimiting("tool-api");
app.MapPost("/tool-api/mta-sts", AnalyzeMtastsAsync).RequireRateLimiting("tool-api");
app.MapPost("/tool-api/rdap", AnalyzeRdapAsync).RequireRateLimiting("tool-api");
app.MapPost("/tool-api/dns-propagation", AnalyzeDnsPropagationAsync).RequireRateLimiting("tool-api");
app.MapPost("/tool-api/ct-subdomains", AnalyzeCtSubdomainsAsync).RequireRateLimiting("tool-api");
app.MapPost("/tool-api/m365-overview/quick", AnalyzeMicrosoft365OverviewQuickAsync).RequireRateLimiting("tool-api");
app.MapPost("/tool-api/m365-overview", AnalyzeMicrosoft365OverviewAsync).RequireRateLimiting("tool-api");
app.MapPost("/tool-api/domain-overview/quick", AnalyzeDomainOverviewQuickAsync).RequireRateLimiting("tool-api");
app.MapPost("/tool-api/domain-overview", AnalyzeDomainOverviewAsync).RequireRateLimiting("tool-api");

if (!string.IsNullOrWhiteSpace(siteRoot) && Directory.Exists(siteRoot)) {
    var fileProvider = new PhysicalFileProvider(siteRoot);
    app.UseDefaultFiles(new DefaultFilesOptions {
        FileProvider = fileProvider
    });
    app.UseStaticFiles(new StaticFileOptions {
        FileProvider = fileProvider,
        ContentTypeProvider = CreateStaticContentTypeProvider()
    });
} else {
    app.Logger.LogWarning("Static site root was not found. Serving API only.");
}

app.Run();

static async Task<Results<Ok<HttpInfo>, ValidationProblem>> AnalyzeHttpHeadersAsync(AnalyzeDomainRequest request, CancellationToken cancellationToken) {
    if (!TryNormalizeDomain(request, out string domainName, out Dictionary<string, string[]> errors)) {
        return TypedResults.ValidationProblem(errors);
    }

    var healthCheck = new DomainHealthCheck();
    await healthCheck.VerifyWebsiteHttps(domainName, cancellationToken).ConfigureAwait(false);
    return TypedResults.Ok(Converters.Convert(healthCheck.HttpAnalysis));
}

static async Task<Results<Ok<SecurityTxtInfo>, ValidationProblem>> AnalyzeSecurityTxtAsync(AnalyzeDomainRequest request, CancellationToken cancellationToken) {
    if (!TryNormalizeDomain(request, out string domainName, out Dictionary<string, string[]> errors)) {
        return TypedResults.ValidationProblem(errors);
    }

    var healthCheck = new DomainHealthCheck();
    await healthCheck.VerifySecurityTxt(domainName, cancellationToken).ConfigureAwait(false);
    return TypedResults.Ok(Converters.Convert(healthCheck.SecurityTXTAnalysis));
}

static async Task<Results<Ok<CertificateInfo>, ValidationProblem>> AnalyzeCertificateAsync(AnalyzeDomainRequest request, CancellationToken cancellationToken) {
    if (!TryNormalizeDomain(request, out string domainName, out Dictionary<string, string[]> errors)) {
        return TypedResults.ValidationProblem(errors);
    }

    var healthCheck = new DomainHealthCheck();
    await healthCheck.VerifyWebsiteCertificate(domainName, cancellationToken: cancellationToken).ConfigureAwait(false);
    return TypedResults.Ok(Converters.Convert(healthCheck.CertificateAnalysis));
}

static async Task<Results<Ok<BimiRecordInfo>, ValidationProblem>> AnalyzeBimiAsync(AnalyzeDomainRequest request, CancellationToken cancellationToken) {
    if (!TryNormalizeDomain(request, out string domainName, out Dictionary<string, string[]> errors)) {
        return TypedResults.ValidationProblem(errors);
    }

    var healthCheck = new DomainHealthCheck();
    await healthCheck.VerifyBIMI(domainName, skipIndicatorDownload: false, cancellationToken: cancellationToken).ConfigureAwait(false);
    return TypedResults.Ok(Converters.Convert(healthCheck.BimiAnalysis));
}

static async Task<Results<Ok<MtastsInfo>, ValidationProblem>> AnalyzeMtastsAsync(AnalyzeDomainRequest request, CancellationToken cancellationToken) {
    if (!TryNormalizeDomain(request, out string domainName, out Dictionary<string, string[]> errors)) {
        return TypedResults.ValidationProblem(errors);
    }

    var healthCheck = new DomainHealthCheck();
    await healthCheck.VerifyMTASTS(domainName, cancellationToken).ConfigureAwait(false);
    return TypedResults.Ok(Converters.Convert(healthCheck.MTASTSAnalysis));
}

static async Task<Results<Ok<RdapInfo>, ValidationProblem>> AnalyzeRdapAsync(AnalyzeDomainRequest request, CancellationToken cancellationToken) {
    if (!TryNormalizeDomain(request, out string domainName, out Dictionary<string, string[]> errors)) {
        return TypedResults.ValidationProblem(errors);
    }

    var healthCheck = new DomainHealthCheck();
    await healthCheck.QueryRDAP(domainName, cancellationToken).ConfigureAwait(false);
    return TypedResults.Ok(Converters.Convert(healthCheck.RdapAnalysis));
}

static async Task<Results<Ok<DnsPropagationSetInfo>, ValidationProblem>> AnalyzeDnsPropagationAsync(AnalyzeDomainRequest request, CancellationToken cancellationToken) {
    if (!TryNormalizeDomain(request, out string domainName, out Dictionary<string, string[]> errors)) {
        return TypedResults.ValidationProblem(errors);
    }

    var healthCheck = new DomainHealthCheck();
    await healthCheck.VerifyDnsPropagationAsync(domainName, cancellationToken).ConfigureAwait(false);
    return TypedResults.Ok(Converters.Convert(healthCheck.DnsPropagationSet));
}

static async Task<Results<Ok<SubdomainsInfo>, ValidationProblem>> AnalyzeCtSubdomainsAsync(AnalyzeDomainRequest request, CancellationToken cancellationToken) {
    if (!TryNormalizeDomain(request, out string domainName, out Dictionary<string, string[]> errors)) {
        return TypedResults.ValidationProblem(errors);
    }

    var analysis = await RunAnalysisAsync(
        domainName,
        static (healthCheck, subject, token) => healthCheck.VerifySubdomainsAsync(subject, token),
        static healthCheck => Converters.Convert(healthCheck.SubdomainsAnalysis),
        cancellationToken,
        configure: static healthCheck => {
            healthCheck.SubdomainsAnalysis.EnableNativeCtLogSource = true;
            healthCheck.SubdomainsAnalysis.UseCertSpotterFallback = true;
        }).ConfigureAwait(false);

    return TypedResults.Ok(analysis.Result);
}

static async Task<Results<Ok<Microsoft365OverviewInfo>, ValidationProblem>> AnalyzeMicrosoft365OverviewAsync(AnalyzeDomainRequest request, IMemoryCache cache, CancellationToken cancellationToken) {
    if (!TryNormalizeDomain(request, out string domainName, out Dictionary<string, string[]> errors)) {
        return TypedResults.ValidationProblem(errors);
    }

    var cachedResult = await GetOrCreateCachedWithStateAsync(
        cache,
        "m365-overview",
        domainName,
        request.ForceRefresh,
        TimeSpan.FromMinutes(15),
        async ct => {
            var generatedAtUtc = DateTimeOffset.UtcNow;
            var tenantTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyMicrosoft365TenantAsync(subject, token),
                static healthCheck => Converters.Convert(healthCheck.Microsoft365TenantAnalysis),
                ct);
            var spfTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifySPF(subject, token),
                static healthCheck => Converters.Convert(healthCheck.SpfAnalysis),
                ct);
            var dkimTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyDKIM(subject, Array.Empty<string>(), token),
                static healthCheck => (IReadOnlyList<DkimRecordInfo>)Converters.Convert(healthCheck.DKIMAnalysis).ToArray(),
                ct);
            var dmarcTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyDMARC(subject, token),
                static healthCheck => Converters.Convert(healthCheck.DmarcAnalysis),
                ct);
            var mxTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyMX(subject, token),
                static healthCheck => Converters.Convert(healthCheck.MXAnalysis),
                ct);
            var mtastsTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyMTASTS(subject, token),
                static healthCheck => Converters.Convert(healthCheck.MTASTSAnalysis),
                ct);
            var tlsRptTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyTLSRPT(subject, token),
                static healthCheck => Converters.Convert(healthCheck.TLSRPTAnalysis),
                ct);
            var bimiTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyBIMI(subject, skipIndicatorDownload: false, cancellationToken: token),
                static healthCheck => Converters.Convert(healthCheck.BimiAnalysis),
                ct);
            var caaTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyCAA(subject, token),
                static healthCheck => Converters.Convert(healthCheck.CAAAnalysis),
                ct);
            var daneTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyDANE(subject, new[] { ServiceType.SMTP, ServiceType.HTTPS }, token),
                static healthCheck => Converters.Convert(healthCheck.DaneAnalysis),
                ct);
            var dnssecTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyDNSSEC(subject, token),
                static healthCheck => DnsSecConverter.Convert(healthCheck.DnsSecAnalysis),
                ct);
            var nsTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyNS(subject, token),
                static healthCheck => Converters.Convert(healthCheck.NSAnalysis),
                ct);

            await Task.WhenAll(
                tenantTask,
                spfTask,
                dkimTask,
                dmarcTask,
                mxTask,
                mtastsTask,
                tlsRptTask,
                bimiTask,
                caaTask,
                daneTask,
                dnssecTask,
                nsTask).ConfigureAwait(false);

            var allAssessments = tenantTask.Result.Assessments
                .Concat(spfTask.Result.Assessments)
                .Concat(dkimTask.Result.Assessments)
                .Concat(dmarcTask.Result.Assessments)
                .Concat(mxTask.Result.Assessments)
                .Concat(mtastsTask.Result.Assessments)
                .Concat(tlsRptTask.Result.Assessments)
                .Concat(bimiTask.Result.Assessments)
                .Concat(caaTask.Result.Assessments)
                .Concat(daneTask.Result.Assessments)
                .Concat(dnssecTask.Result.Assessments)
                .Concat(nsTask.Result.Assessments)
                .ToArray();

            var overview = Converters.ConvertMicrosoft365Overview(
                domainName,
                tenantTask.Result.Result,
                spfTask.Result.Result,
                dkimTask.Result.Result,
                dmarcTask.Result.Result,
                mxTask.Result.Result,
                mtastsTask.Result.Result,
                tlsRptTask.Result.Result,
                bimiTask.Result.Result,
                caaTask.Result.Result,
                daneTask.Result.Result,
                dnssecTask.Result.Result,
                nsTask.Result.Result,
                allAssessments);

            overview.IsPartial = false;
            overview.StageLabel = "Deep DD evidence complete";
            overview.PendingSections = Array.Empty<string>();
            overview.GeneratedAtUtc = generatedAtUtc;
            overview.CompletedAtUtc = generatedAtUtc;
            return overview;
        },
        cancellationToken).ConfigureAwait(false);

    var result = cachedResult.Result;
    result.ServedFromCache = cachedResult.FromCache;
    return TypedResults.Ok(result);
}

static async Task<Results<Ok<Microsoft365OverviewInfo>, ValidationProblem>> AnalyzeMicrosoft365OverviewQuickAsync(AnalyzeDomainRequest request, IMemoryCache cache, CancellationToken cancellationToken) {
    if (!TryNormalizeDomain(request, out string domainName, out Dictionary<string, string[]> errors)) {
        return TypedResults.ValidationProblem(errors);
    }

    var cachedResult = await GetOrCreateCachedWithStateAsync(
        cache,
        "m365-overview-quick",
        domainName,
        request.ForceRefresh,
        TimeSpan.FromMinutes(5),
        async ct => {
            var generatedAtUtc = DateTimeOffset.UtcNow;
            var tenantTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyMicrosoft365TenantAsync(subject, token),
                static healthCheck => Converters.Convert(healthCheck.Microsoft365TenantAnalysis),
                ct);
            var spfTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifySPF(subject, token),
                static healthCheck => Converters.Convert(healthCheck.SpfAnalysis),
                ct);
            var dkimTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyDKIM(subject, Array.Empty<string>(), token),
                static healthCheck => (IReadOnlyList<DkimRecordInfo>)Converters.Convert(healthCheck.DKIMAnalysis).ToArray(),
                ct);
            var dmarcTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyDMARC(subject, token),
                static healthCheck => Converters.Convert(healthCheck.DmarcAnalysis),
                ct);
            var mxTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyMX(subject, token),
                static healthCheck => Converters.Convert(healthCheck.MXAnalysis),
                ct);
            var nsTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyNS(subject, token),
                static healthCheck => Converters.Convert(healthCheck.NSAnalysis),
                ct);

            await Task.WhenAll(tenantTask, spfTask, dkimTask, dmarcTask, mxTask, nsTask).ConfigureAwait(false);

            var assessments = tenantTask.Result.Assessments
                .Concat(spfTask.Result.Assessments)
                .Concat(dkimTask.Result.Assessments)
                .Concat(dmarcTask.Result.Assessments)
                .Concat(mxTask.Result.Assessments)
                .Concat(nsTask.Result.Assessments)
                .ToArray();

            var overview = Converters.ConvertMicrosoft365Overview(
                domainName,
                tenantTask.Result.Result,
                spfTask.Result.Result,
                dkimTask.Result.Result,
                dmarcTask.Result.Result,
                mxTask.Result.Result,
                new MtastsInfo(),
                new TlsRptInfo(),
                new BimiRecordInfo(),
                new CaaInfo(),
                new DaneRecordInfo(),
                new DnsSecInfo(),
                nsTask.Result.Result,
                assessments);

            overview.MailDnsChecks = MarkPendingChecks(
                overview.MailDnsChecks,
                "mta-sts",
                "tls-rpt",
                "bimi",
                "caa",
                "dane",
                "dnssec");

            overview.IsPartial = true;
            overview.StageLabel = "Quick posture ready";
            overview.PendingSections = new[] {
                "MTA-STS",
                "TLS-RPT",
                "BIMI",
                "CAA",
                "DANE",
                "DNSSEC",
                "Deep recommendations"
            };
            overview.GeneratedAtUtc = generatedAtUtc;
            overview.CompletedAtUtc = null;
            return overview;
        },
        cancellationToken).ConfigureAwait(false);

    var result = cachedResult.Result;
    result.ServedFromCache = cachedResult.FromCache;
    return TypedResults.Ok(result);
}

static async Task<Results<Ok<DomainOverviewInfo>, ValidationProblem>> AnalyzeDomainOverviewAsync(AnalyzeDomainRequest request, IMemoryCache cache, CancellationToken cancellationToken) {
    if (!TryNormalizeDomain(request, out string domainName, out Dictionary<string, string[]> errors)) {
        return TypedResults.ValidationProblem(errors);
    }

    var cachedResult = await GetOrCreateCachedWithStateAsync(
        cache,
        "domain-overview",
        domainName,
        request.ForceRefresh,
        TimeSpan.FromMinutes(10),
        async ct => {
            var generatedAtUtc = DateTimeOffset.UtcNow;
            var dnsInventoryTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyDnsInventoryAsync(subject, token),
                static healthCheck => Converters.Convert(healthCheck.DnsInventoryAnalysis),
                ct);
            var subdomainsTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifySubdomainsAsync(subject, token),
                static healthCheck => Converters.Convert(healthCheck.SubdomainsAnalysis),
                ct,
                static healthCheck => {
                    healthCheck.SubdomainsAnalysis.EnableNativeCtLogSource = true;
                    healthCheck.SubdomainsAnalysis.UseCertSpotterFallback = true;
                });
            var spfTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifySPF(subject, token),
                static healthCheck => Converters.Convert(healthCheck.SpfAnalysis),
                ct);
            var dkimTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyDKIM(subject, Array.Empty<string>(), token),
                static healthCheck => (IReadOnlyList<DkimRecordInfo>)Converters.Convert(healthCheck.DKIMAnalysis).ToArray(),
                ct);
            var dmarcTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyDMARC(subject, token),
                static healthCheck => Converters.Convert(healthCheck.DmarcAnalysis),
                ct);
            var mxTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyMX(subject, token),
                static healthCheck => Converters.Convert(healthCheck.MXAnalysis),
                ct);
            var mtastsTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyMTASTS(subject, token),
                static healthCheck => Converters.Convert(healthCheck.MTASTSAnalysis),
                ct);
            var tlsRptTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyTLSRPT(subject, token),
                static healthCheck => Converters.Convert(healthCheck.TLSRPTAnalysis),
                ct);
            var bimiTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyBIMI(subject, skipIndicatorDownload: false, cancellationToken: token),
                static healthCheck => Converters.Convert(healthCheck.BimiAnalysis),
                ct);
            var caaTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyCAA(subject, token),
                static healthCheck => Converters.Convert(healthCheck.CAAAnalysis),
                ct);
            var daneTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyDANE(subject, new[] { ServiceType.SMTP, ServiceType.HTTPS }, token),
                static healthCheck => Converters.Convert(healthCheck.DaneAnalysis),
                ct);
            var dnssecTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyDNSSEC(subject, token),
                static healthCheck => DnsSecConverter.Convert(healthCheck.DnsSecAnalysis),
                ct);
            var nsTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyNS(subject, token),
                static healthCheck => Converters.Convert(healthCheck.NSAnalysis),
                ct);
            var soaTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifySOA(subject, token),
                static healthCheck => Converters.Convert(healthCheck.SOAAnalysis),
                ct);
            var httpTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyWebsiteHttps(subject, token),
                static healthCheck => Converters.Convert(healthCheck.HttpAnalysis),
                ct);
            var certTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyWebsiteCertificate(subject, cancellationToken: token),
                static healthCheck => Converters.Convert(healthCheck.CertificateAnalysis),
                ct);
            var securityTxtTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifySecurityTxt(subject, token),
                static healthCheck => Converters.Convert(healthCheck.SecurityTXTAnalysis),
                ct);
            var rdapTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.QueryRDAP(subject, token),
                static healthCheck => Converters.Convert(healthCheck.RdapAnalysis),
                ct);
            var dnsblTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyDNSBLWithMode(subject, DomainIpScanMode.MxAOnly, cancellationToken: token),
                static healthCheck => Converters.Convert(healthCheck.DNSBLAnalysis),
                ct);

            await Task.WhenAll(
                dnsInventoryTask,
                subdomainsTask,
                spfTask,
                dkimTask,
                dmarcTask,
                mxTask,
                mtastsTask,
                tlsRptTask,
                bimiTask,
                caaTask,
                daneTask,
                dnssecTask,
                nsTask,
                soaTask,
                httpTask,
                certTask,
                securityTxtTask,
                rdapTask,
                dnsblTask).ConfigureAwait(false);

            var allAssessments = dnsInventoryTask.Result.Assessments
                .Concat(subdomainsTask.Result.Assessments)
                .Concat(spfTask.Result.Assessments)
                .Concat(dkimTask.Result.Assessments)
                .Concat(dmarcTask.Result.Assessments)
                .Concat(mxTask.Result.Assessments)
                .Concat(mtastsTask.Result.Assessments)
                .Concat(tlsRptTask.Result.Assessments)
                .Concat(bimiTask.Result.Assessments)
                .Concat(caaTask.Result.Assessments)
                .Concat(daneTask.Result.Assessments)
                .Concat(dnssecTask.Result.Assessments)
                .Concat(nsTask.Result.Assessments)
                .Concat(soaTask.Result.Assessments)
                .Concat(httpTask.Result.Assessments)
                .Concat(certTask.Result.Assessments)
                .Concat(securityTxtTask.Result.Assessments)
                .Concat(rdapTask.Result.Assessments)
                .Concat(dnsblTask.Result.Assessments)
                .ToArray();

            var overview = Converters.ConvertDomainOverview(
                domainName,
                dnsInventoryTask.Result.Result,
                spfTask.Result.Result,
                dkimTask.Result.Result,
                dmarcTask.Result.Result,
                mxTask.Result.Result,
                mtastsTask.Result.Result,
                tlsRptTask.Result.Result,
                bimiTask.Result.Result,
                caaTask.Result.Result,
                daneTask.Result.Result,
                dnssecTask.Result.Result,
                nsTask.Result.Result,
                soaTask.Result.Result,
                httpTask.Result.Result,
                certTask.Result.Result,
                securityTxtTask.Result.Result,
                rdapTask.Result.Result,
                dnsblTask.Result.Result,
                subdomainsTask.Result.Result,
                allAssessments);

            overview.IsPartial = false;
            overview.StageLabel = "Deep DD evidence complete";
            overview.PendingSections = Array.Empty<string>();
            overview.GeneratedAtUtc = generatedAtUtc;
            overview.CompletedAtUtc = generatedAtUtc;
            return overview;
        },
        cancellationToken).ConfigureAwait(false);

    var result = cachedResult.Result;
    result.ServedFromCache = cachedResult.FromCache;
    return TypedResults.Ok(result);
}

static async Task<Results<Ok<DomainOverviewInfo>, ValidationProblem>> AnalyzeDomainOverviewQuickAsync(AnalyzeDomainRequest request, IMemoryCache cache, CancellationToken cancellationToken) {
    if (!TryNormalizeDomain(request, out string domainName, out Dictionary<string, string[]> errors)) {
        return TypedResults.ValidationProblem(errors);
    }

    var cachedResult = await GetOrCreateCachedWithStateAsync(
        cache,
        "domain-overview-quick",
        domainName,
        request.ForceRefresh,
        TimeSpan.FromMinutes(5),
        async ct => {
            var generatedAtUtc = DateTimeOffset.UtcNow;
            var dnsInventoryTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyDnsInventoryAsync(subject, token),
                static healthCheck => Converters.Convert(healthCheck.DnsInventoryAnalysis),
                ct);
            var spfTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifySPF(subject, token),
                static healthCheck => Converters.Convert(healthCheck.SpfAnalysis),
                ct);
            var dkimTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyDKIM(subject, Array.Empty<string>(), token),
                static healthCheck => (IReadOnlyList<DkimRecordInfo>)Converters.Convert(healthCheck.DKIMAnalysis).ToArray(),
                ct);
            var dmarcTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyDMARC(subject, token),
                static healthCheck => Converters.Convert(healthCheck.DmarcAnalysis),
                ct);
            var mxTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyMX(subject, token),
                static healthCheck => Converters.Convert(healthCheck.MXAnalysis),
                ct);
            var nsTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyNS(subject, token),
                static healthCheck => Converters.Convert(healthCheck.NSAnalysis),
                ct);
            var soaTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifySOA(subject, token),
                static healthCheck => Converters.Convert(healthCheck.SOAAnalysis),
                ct);
            var httpTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifyWebsiteHttps(subject, token),
                static healthCheck => Converters.Convert(healthCheck.HttpAnalysis),
                ct);
            var securityTxtTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.VerifySecurityTxt(subject, token),
                static healthCheck => Converters.Convert(healthCheck.SecurityTXTAnalysis),
                ct);
            var rdapTask = RunAnalysisAsync(
                domainName,
                static (healthCheck, subject, token) => healthCheck.QueryRDAP(subject, token),
                static healthCheck => Converters.Convert(healthCheck.RdapAnalysis),
                ct);

            await Task.WhenAll(
                dnsInventoryTask,
                spfTask,
                dkimTask,
                dmarcTask,
                mxTask,
                nsTask,
                soaTask,
                httpTask,
                securityTxtTask,
                rdapTask).ConfigureAwait(false);

            var assessments = dnsInventoryTask.Result.Assessments
                .Concat(spfTask.Result.Assessments)
                .Concat(dkimTask.Result.Assessments)
                .Concat(dmarcTask.Result.Assessments)
                .Concat(mxTask.Result.Assessments)
                .Concat(nsTask.Result.Assessments)
                .Concat(soaTask.Result.Assessments)
                .Concat(httpTask.Result.Assessments)
                .Concat(securityTxtTask.Result.Assessments)
                .Concat(rdapTask.Result.Assessments)
                .ToArray();

            var overview = Converters.ConvertDomainOverview(
                domainName,
                dnsInventoryTask.Result.Result,
                spfTask.Result.Result,
                dkimTask.Result.Result,
                dmarcTask.Result.Result,
                mxTask.Result.Result,
                new MtastsInfo(),
                new TlsRptInfo(),
                new BimiRecordInfo(),
                new CaaInfo(),
                new DaneRecordInfo(),
                new DnsSecInfo(),
                nsTask.Result.Result,
                soaTask.Result.Result,
                httpTask.Result.Result,
                new CertificateInfo(),
                securityTxtTask.Result.Result,
                rdapTask.Result.Result,
                new DnsblInfo(),
                new SubdomainsInfo(),
                assessments);

            overview.MailDnsChecks = MarkPendingChecks(
                overview.MailDnsChecks,
                "mta-sts",
                "tls-rpt",
                "bimi",
                "caa",
                "dane",
                "dnssec");
            overview.WebRegistrationChecks = MarkPendingChecks(
                overview.WebRegistrationChecks,
                "cert",
                "dnsbl",
                "subdomains");

            overview.IsPartial = true;
            overview.StageLabel = "Quick posture ready";
            overview.PendingSections = new[] {
                "Certificate",
                "DNSBL",
                "Subdomain discovery",
                "MTA-STS",
                "TLS-RPT",
                "BIMI",
                "CAA",
                "DANE",
                "DNSSEC",
                "Deep recommendations"
            };
            overview.GeneratedAtUtc = generatedAtUtc;
            overview.CompletedAtUtc = null;
            return overview;
        },
        cancellationToken).ConfigureAwait(false);

    var result = cachedResult.Result;
    result.ServedFromCache = cachedResult.FromCache;
    return TypedResults.Ok(result);
}

static string? ResolveSiteRoot(IConfiguration configuration, IWebHostEnvironment environment) {
    var configured = configuration["SiteRoot"];
    if (!string.IsNullOrWhiteSpace(configured) && Directory.Exists(configured)) {
        return Path.GetFullPath(configured);
    }

    var candidates = new[] {
        BuildSiteRootCandidate(Directory.GetCurrentDirectory(), "..", "Website", "_site"),
        BuildSiteRootCandidate(Directory.GetCurrentDirectory(), "Website", "_site"),
        BuildSiteRootCandidate(environment.ContentRootPath, "..", "Website", "_site"),
        BuildSiteRootCandidate(AppContext.BaseDirectory, "..", "..", "..", "..", "Website", "_site")
    };

    foreach (var fullPath in candidates.Where(Directory.Exists)) {
        return fullPath;
    }

    return null;
}

static string BuildSiteRootCandidate(string basePath, params string[] segments) {
    var pathSegments = new string[segments.Length + 1];
    pathSegments[0] = basePath;
    Array.Copy(segments, 0, pathSegments, 1, segments.Length);
    return Path.GetFullPath(Path.Combine(pathSegments));
}

static string[] ResolveAllowedOrigins(IConfiguration configuration, IWebHostEnvironment environment, out bool usingFallbackOrigins) {
    var configuredOrigins = configuration.GetSection("Cors:AllowedOrigins").Get<string[]>();
    if (configuredOrigins is { Length: > 0 }) {
        usingFallbackOrigins = false;
        return configuredOrigins
            .Where(static origin => !string.IsNullOrWhiteSpace(origin))
            .Select(static origin => origin.Trim().TrimEnd('/'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    var inlineOrigins = configuration["Cors:AllowedOrigins"];
    if (!string.IsNullOrWhiteSpace(inlineOrigins)) {
        usingFallbackOrigins = false;
        return inlineOrigins
            .Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(static origin => origin.Trim().TrimEnd('/'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    usingFallbackOrigins = true;
    if (environment.IsDevelopment()) {
        return new[] {
            "http://localhost:8097",
            "http://localhost:8098",
            "http://127.0.0.1:8097",
            "http://127.0.0.1:8098"
        };
    }

    return new[] {
        "https://domaindetective.dev",
        "https://www.domaindetective.dev"
    };
}

static FileExtensionContentTypeProvider CreateStaticContentTypeProvider() {
    var provider = new FileExtensionContentTypeProvider();
    provider.Mappings[".wasm"] = "application/wasm";
    provider.Mappings[".webcil"] = "application/octet-stream";
    provider.Mappings[".dat"] = "application/octet-stream";
    provider.Mappings[".dll"] = "application/octet-stream";
    provider.Mappings[".pdb"] = "application/octet-stream";
    provider.Mappings[".mjs"] = "text/javascript";
    return provider;
}

static bool TryNormalizeDomain(AnalyzeDomainRequest request, out string domainName, out Dictionary<string, string[]> errors) {
    errors = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
    var requestedDomain = request.Domain?.Trim() ?? string.Empty;
    if (string.IsNullOrWhiteSpace(requestedDomain)) {
        domainName = string.Empty;
        errors["domain"] = new[] { "A domain name is required." };
        return false;
    }

    if (TryNormalizeDomainName(requestedDomain, out domainName, out var errorMessage)) {
        return true;
    }

    domainName = string.Empty;
    errors["domain"] = new[] { errorMessage };
    return false;
}

static bool TryNormalizeDomainName(string value, out string domainName, out string errorMessage) {
    domainName = string.Empty;
    errorMessage = "Enter a valid public domain name.";

    if (string.IsNullOrWhiteSpace(value)) {
        errorMessage = "A domain name is required.";
        return false;
    }

    var candidate = value.Trim();
    if (candidate.Contains("://", StringComparison.Ordinal) ||
        candidate.Contains('/', StringComparison.Ordinal) ||
        candidate.Contains('\\', StringComparison.Ordinal) ||
        candidate.Contains('?', StringComparison.Ordinal) ||
        candidate.Contains('#', StringComparison.Ordinal) ||
        candidate.Any(char.IsWhiteSpace)) {
        return false;
    }

    candidate = candidate.TrimEnd('.');
    if (candidate.Length == 0 || candidate.Length > 253) {
        return false;
    }

    if (IPAddress.TryParse(candidate, out _)) {
        errorMessage = "Enter a public domain name, not an IP address.";
        return false;
    }

    try {
        candidate = new IdnMapping().GetAscii(candidate);
    } catch (ArgumentException) {
        return false;
    }

    if (candidate.Equals("localhost", StringComparison.OrdinalIgnoreCase) || candidate.Contains("..", StringComparison.Ordinal)) {
        return false;
    }

    var labels = candidate.Split('.');
    if (labels.Length < 2) {
        return false;
    }

    foreach (var label in labels) {
        if (label.Length == 0 || label.Length > 63) {
            return false;
        }

        if (label[0] == '-' || label[^1] == '-') {
            return false;
        }

        if (label.Any(static character => !(char.IsLetterOrDigit(character) || character == '-'))) {
            return false;
        }
    }

    if (labels[^1].All(char.IsDigit)) {
        return false;
    }

    domainName = candidate.ToLowerInvariant();
    return true;
}

static async Task<(T Result, Assessment[] Assessments)> RunAnalysisAsync<T>(
    string domainName,
    Func<DomainHealthCheck, string, CancellationToken, Task> verifyAsync,
    Func<DomainHealthCheck, T> convert,
    CancellationToken cancellationToken,
    Action<DomainHealthCheck>? configure = null) {
    var healthCheck = new DomainHealthCheck();
    configure?.Invoke(healthCheck);
    await verifyAsync(healthCheck, domainName, cancellationToken).ConfigureAwait(false);
    return (convert(healthCheck), healthCheck.GetAllAssessments().ToArray());
}

static async Task<(T Result, bool FromCache)> GetOrCreateCachedWithStateAsync<T>(
    IMemoryCache cache,
    string prefix,
    string domainName,
    bool forceRefresh,
    TimeSpan ttl,
    Func<CancellationToken, Task<T>> factory,
    CancellationToken cancellationToken) {
    var cacheKey = $"{prefix}:{domainName.ToLowerInvariant()}";
    if (!forceRefresh && cache.TryGetValue(cacheKey, out T? cached) && cached is not null) {
        return (cached, true);
    }

    using var cacheLease = await CacheStampedeLocks.AcquireAsync(cacheKey, cancellationToken).ConfigureAwait(false);
    if (!forceRefresh && cache.TryGetValue(cacheKey, out cached) && cached is not null) {
        return (cached, true);
    }

    var created = await factory(cancellationToken).ConfigureAwait(false);
    cache.Set(cacheKey, created, ttl);
    return (created, false);
}

static AggregateCheckStatusInfo[] MarkPendingChecks(IReadOnlyList<AggregateCheckStatusInfo> checks, params string[] pendingKeys) {
    var pending = new HashSet<string>(pendingKeys, StringComparer.OrdinalIgnoreCase);
    return checks
        .Select(check => pending.Contains(check.Key)
            ? new AggregateCheckStatusInfo {
                Key = check.Key,
                Label = check.Label,
                State = AggregateCheckState.Info,
                Value = "Pending",
                Detail = "Deep DD scan is still running for this control."
            }
            : check)
        .ToArray();
}

public sealed class AnalyzeDomainRequest {
    public string Domain { get; set; } = string.Empty;
    public bool ForceRefresh { get; set; }
}

file static class CacheStampedeLocks {
    private static readonly ConcurrentDictionary<string, RefCountedLock> PerKey = new(StringComparer.OrdinalIgnoreCase);

    internal static async Task<Lease> AcquireAsync(string key, CancellationToken cancellationToken) {
        var created = new RefCountedLock();
        var gate = PerKey.GetOrAdd(key, created);
        if (!ReferenceEquals(gate, created)) {
            Interlocked.Increment(ref gate.RefCount);
        }

        await gate.Semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        return new Lease(key, gate);
    }

    internal readonly struct Lease : IDisposable {
        private readonly string _key;
        private readonly RefCountedLock _gate;

        internal Lease(string key, RefCountedLock gate) {
            _key = key;
            _gate = gate;
        }

        public void Dispose() {
            _gate.Semaphore.Release();
            if (Interlocked.Decrement(ref _gate.RefCount) == 0 &&
                PerKey.TryRemove(new KeyValuePair<string, RefCountedLock>(_key, _gate))) {
                _gate.Semaphore.Dispose();
            }
        }
    }

    internal sealed class RefCountedLock {
        internal readonly SemaphoreSlim Semaphore = new(1, 1);
        internal int RefCount = 1;
    }
}
