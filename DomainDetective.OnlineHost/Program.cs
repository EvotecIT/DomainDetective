using DomainDetective;
using DomainDetective.Views;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.FileProviders;
using System.Linq;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options => {
    options.AddDefaultPolicy(policy => {
        policy.AllowAnyOrigin()
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});
builder.Services.AddMemoryCache();

var app = builder.Build();
var siteRoot = ResolveSiteRoot(app.Configuration, app.Environment);

app.UseCors();

app.MapGet("/tool-api/health", () => TypedResults.Ok(new {
    status = "ok",
    siteRootExists = siteRoot != null && Directory.Exists(siteRoot)
}));

app.MapPost("/tool-api/http-headers", AnalyzeHttpHeadersAsync);
app.MapPost("/tool-api/security-txt", AnalyzeSecurityTxtAsync);
app.MapPost("/tool-api/cert-check", AnalyzeCertificateAsync);
app.MapPost("/tool-api/bimi", AnalyzeBimiAsync);
app.MapPost("/tool-api/mta-sts", AnalyzeMtastsAsync);
app.MapPost("/tool-api/rdap", AnalyzeRdapAsync);
app.MapPost("/tool-api/dns-propagation", AnalyzeDnsPropagationAsync);
app.MapPost("/tool-api/ct-subdomains", AnalyzeCtSubdomainsAsync);
app.MapPost("/tool-api/m365-overview/quick", AnalyzeMicrosoft365OverviewQuickAsync);
app.MapPost("/tool-api/m365-overview", AnalyzeMicrosoft365OverviewAsync);
app.MapPost("/tool-api/domain-overview/quick", AnalyzeDomainOverviewQuickAsync);
app.MapPost("/tool-api/domain-overview", AnalyzeDomainOverviewAsync);

if (!string.IsNullOrWhiteSpace(siteRoot) && Directory.Exists(siteRoot)) {
    var fileProvider = new PhysicalFileProvider(siteRoot);
    app.UseDefaultFiles(new DefaultFilesOptions {
        FileProvider = fileProvider
    });
    app.UseStaticFiles(new StaticFileOptions {
        FileProvider = fileProvider,
        ServeUnknownFileTypes = true
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

    var healthCheck = new DomainHealthCheck();
    healthCheck.SubdomainsAnalysis.EnableNativeCtLogSource = true;
    healthCheck.SubdomainsAnalysis.UseCertSpotterFallback = true;
    await healthCheck.VerifySubdomainsAsync(domainName, cancellationToken).ConfigureAwait(false);
    return TypedResults.Ok(Converters.Convert(healthCheck.SubdomainsAnalysis));
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
        Path.Combine(Directory.GetCurrentDirectory(), "..", "Website", "_site"),
        Path.Combine(Directory.GetCurrentDirectory(), "Website", "_site"),
        Path.Combine(environment.ContentRootPath, "..", "Website", "_site"),
        Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Website", "_site")
    };

    foreach (var candidate in candidates) {
        var fullPath = Path.GetFullPath(candidate);
        if (Directory.Exists(fullPath)) {
            return fullPath;
        }
    }

    return null;
}

static bool TryNormalizeDomain(AnalyzeDomainRequest request, out string domainName, out Dictionary<string, string[]> errors) {
    errors = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
    domainName = request.Domain?.Trim() ?? string.Empty;
    if (!string.IsNullOrWhiteSpace(domainName)) {
        return true;
    }

    errors["domain"] = new[] { "A domain name is required." };
    return false;
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
