using DomainDetective.Providers.Email;
using DomainDetective.Views;

namespace DomainDetective.Toolbox.Services;

public sealed class BrowserOverviewService {
    private readonly BrowserDnsService _dnsService;

    public BrowserOverviewService(BrowserDnsService dnsService) {
        _dnsService = dnsService;
    }

    public async Task<Microsoft365OverviewInfo> AnalyzeMicrosoft365OverviewLiteAsync(string domainName, CancellationToken cancellationToken = default) {
        var generatedAtUtc = DateTimeOffset.UtcNow;
        var dnsInventoryTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyDnsInventoryAsync(subject, token),
            static healthCheck => Converters.Convert(healthCheck.DnsInventoryAnalysis),
            cancellationToken);
        var spfTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifySPF(subject, token),
            static healthCheck => Converters.Convert(healthCheck.SpfAnalysis),
            cancellationToken);
        var dkimTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyDKIM(subject, Array.Empty<string>(), token),
            static healthCheck => (IReadOnlyList<DkimRecordInfo>)Converters.Convert(healthCheck.DKIMAnalysis).ToArray(),
            cancellationToken);
        var dmarcTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyDMARC(subject, token),
            static healthCheck => Converters.Convert(healthCheck.DmarcAnalysis),
            cancellationToken);
        var mxTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyMX(subject, token),
            static healthCheck => Converters.Convert(healthCheck.MXAnalysis),
            cancellationToken);
        var mtastsTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyMTASTSBootstrap(subject, token),
            static healthCheck => Converters.Convert(healthCheck.MTASTSAnalysis),
            cancellationToken);
        var tlsRptTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyTLSRPT(subject, token),
            static healthCheck => Converters.Convert(healthCheck.TLSRPTAnalysis),
            cancellationToken);
        var bimiTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyBIMI(subject, skipIndicatorDownload: true, cancellationToken: token),
            static healthCheck => Converters.Convert(healthCheck.BimiAnalysis),
            cancellationToken);
        var caaTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyCAA(subject, token),
            static healthCheck => Converters.Convert(healthCheck.CAAAnalysis),
            cancellationToken);
        var daneTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyDANE(subject, new[] { ServiceType.SMTP, ServiceType.HTTPS }, token),
            static healthCheck => Converters.Convert(healthCheck.DaneAnalysis),
            cancellationToken);
        var dnssecTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyDNSSEC(subject, token),
            static healthCheck => DnsSecConverter.Convert(healthCheck.DnsSecAnalysis),
            cancellationToken);
        var nsTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyNS(subject, token),
            static healthCheck => Converters.Convert(healthCheck.NSAnalysis),
            cancellationToken);

        await Task.WhenAll(
            dnsInventoryTask,
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

        var tenant = BuildBrowserMicrosoft365Tenant(domainName, dnsInventoryTask.Result.Result);
        var assessments = dnsInventoryTask.Result.Assessments
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
            tenant,
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
            assessments,
            browserLimited: true);

        overview.IsPartial = false;
        overview.IsBrowserLimited = true;
        overview.StageLabel = "Web edition overview ready";
        overview.GeneratedAtUtc = generatedAtUtc;
        overview.CompletedAtUtc = generatedAtUtc;
        overview.PendingSections = Array.Empty<string>();
        overview.UnavailableSections = new[] {
            "Identity",
            "Services",
            "Domains"
        };
        return overview;
    }

    public async Task<DomainOverviewInfo> AnalyzeDomainOverviewLiteAsync(string domainName, CancellationToken cancellationToken = default) {
        var generatedAtUtc = DateTimeOffset.UtcNow;
        var dnsInventoryTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyDnsInventoryAsync(subject, token),
            static healthCheck => Converters.Convert(healthCheck.DnsInventoryAnalysis),
            cancellationToken);
        var spfTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifySPF(subject, token),
            static healthCheck => Converters.Convert(healthCheck.SpfAnalysis),
            cancellationToken);
        var dkimTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyDKIM(subject, Array.Empty<string>(), token),
            static healthCheck => (IReadOnlyList<DkimRecordInfo>)Converters.Convert(healthCheck.DKIMAnalysis).ToArray(),
            cancellationToken);
        var dmarcTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyDMARC(subject, token),
            static healthCheck => Converters.Convert(healthCheck.DmarcAnalysis),
            cancellationToken);
        var mxTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyMX(subject, token),
            static healthCheck => Converters.Convert(healthCheck.MXAnalysis),
            cancellationToken);
        var mtastsTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyMTASTSBootstrap(subject, token),
            static healthCheck => Converters.Convert(healthCheck.MTASTSAnalysis),
            cancellationToken);
        var tlsRptTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyTLSRPT(subject, token),
            static healthCheck => Converters.Convert(healthCheck.TLSRPTAnalysis),
            cancellationToken);
        var bimiTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyBIMI(subject, skipIndicatorDownload: true, cancellationToken: token),
            static healthCheck => Converters.Convert(healthCheck.BimiAnalysis),
            cancellationToken);
        var caaTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyCAA(subject, token),
            static healthCheck => Converters.Convert(healthCheck.CAAAnalysis),
            cancellationToken);
        var daneTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyDANE(subject, new[] { ServiceType.SMTP, ServiceType.HTTPS }, token),
            static healthCheck => Converters.Convert(healthCheck.DaneAnalysis),
            cancellationToken);
        var dnssecTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyDNSSEC(subject, token),
            static healthCheck => DnsSecConverter.Convert(healthCheck.DnsSecAnalysis),
            cancellationToken);
        var nsTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyNS(subject, token),
            static healthCheck => Converters.Convert(healthCheck.NSAnalysis),
            cancellationToken);
        var soaTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifySOA(subject, token),
            static healthCheck => Converters.Convert(healthCheck.SOAAnalysis),
            cancellationToken);
        var dnsblTask = RunAnalysisAsync(
            domainName,
            static (healthCheck, subject, token) => healthCheck.VerifyDNSBLWithMode(subject, DomainIpScanMode.MxAOnly, cancellationToken: token),
            static healthCheck => Converters.Convert(healthCheck.DNSBLAnalysis),
            cancellationToken);

        await Task.WhenAll(
            dnsInventoryTask,
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
            dnsblTask).ConfigureAwait(false);

        var assessments = dnsInventoryTask.Result.Assessments
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
            new HttpInfo(),
            new CertificateInfo(),
            new SecurityTxtInfo(),
            new RdapInfo(),
            dnsblTask.Result.Result,
            new SubdomainsInfo(),
            assessments,
            browserLimited: true);

        overview.IsPartial = false;
        overview.IsBrowserLimited = true;
        overview.StageLabel = "Web edition overview ready";
        overview.GeneratedAtUtc = generatedAtUtc;
        overview.CompletedAtUtc = generatedAtUtc;
        overview.PendingSections = Array.Empty<string>();
        overview.UnavailableSections = new[] {
            "Web and registration",
            "Exposure"
        };
        return overview;
    }

    private static Microsoft365TenantInfo BuildBrowserMicrosoft365Tenant(string domainName, DnsInventoryInfo dnsInventory) {
        var highlights = new List<string>();
        if (dnsInventory.MailProvider != MailProviderKind.Unknown) {
            highlights.Add("Mail provider hint: " + dnsInventory.MailProvider);
        }

        if (dnsInventory.DetectedDnsApplications.Count > 0) {
            highlights.Add($"Detected {dnsInventory.DetectedDnsApplications.Count} DNS application hint(s).");
        }

        highlights.Add("Web edition: identity, tenant, and auth probing are unavailable.");

        return new Microsoft365TenantInfo {
            Subject = domainName,
            TenantName = domainName,
            DetectedDnsApplications = dnsInventory.DetectedDnsApplications,
            Highlights = highlights,
            Summary = "Web edition Microsoft 365 overview built from public DNS and mail posture only."
        };
    }

    private async Task<(T Result, Assessment[] Assessments)> RunAnalysisAsync<T>(
        string domainName,
        Func<DomainHealthCheck, string, CancellationToken, Task> verifyAsync,
        Func<DomainHealthCheck, T> convert,
        CancellationToken cancellationToken,
        Action<DomainHealthCheck>? configure = null) {
        var healthCheck = _dnsService.CreateHealthCheck();
        configure?.Invoke(healthCheck);
        await verifyAsync(healthCheck, domainName, cancellationToken).ConfigureAwait(false);
        return (convert(healthCheck), healthCheck.GetAllAssessments().ToArray());
    }
}
