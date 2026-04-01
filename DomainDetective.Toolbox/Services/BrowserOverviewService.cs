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
        var healthCheck = _dnsService.CreateHealthCheck();

        await healthCheck.VerifyDnsInventoryAsync(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifySPF(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyDKIM(domainName, Array.Empty<string>(), cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyDMARC(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyMX(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyMTASTSBootstrap(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyTLSRPT(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyBIMI(domainName, skipIndicatorDownload: true, cancellationToken: cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyCAA(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyDANE(domainName, new[] { ServiceType.SMTP, ServiceType.HTTPS }, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyDNSSEC(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyNS(domainName, cancellationToken).ConfigureAwait(false);

        var dnsInventory = Converters.Convert(healthCheck.DnsInventoryAnalysis);
        var tenant = BuildBrowserMicrosoft365Tenant(domainName, dnsInventory);
        var assessments = healthCheck.GetAllAssessments().ToArray();

        var overview = Converters.ConvertMicrosoft365Overview(
            domainName,
            tenant,
            Converters.Convert(healthCheck.SpfAnalysis),
            Converters.Convert(healthCheck.DKIMAnalysis).ToArray(),
            Converters.Convert(healthCheck.DmarcAnalysis),
            Converters.Convert(healthCheck.MXAnalysis),
            Converters.Convert(healthCheck.MTASTSAnalysis),
            Converters.Convert(healthCheck.TLSRPTAnalysis),
            Converters.Convert(healthCheck.BimiAnalysis),
            Converters.Convert(healthCheck.CAAAnalysis),
            Converters.Convert(healthCheck.DaneAnalysis),
            DnsSecConverter.Convert(healthCheck.DnsSecAnalysis),
            Converters.Convert(healthCheck.NSAnalysis),
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
        var healthCheck = _dnsService.CreateHealthCheck();

        await healthCheck.VerifyDnsInventoryAsync(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifySPF(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyDKIM(domainName, Array.Empty<string>(), cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyDMARC(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyMX(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyMTASTSBootstrap(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyTLSRPT(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyBIMI(domainName, skipIndicatorDownload: true, cancellationToken: cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyCAA(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyDANE(domainName, new[] { ServiceType.SMTP, ServiceType.HTTPS }, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyDNSSEC(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyNS(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifySOA(domainName, cancellationToken).ConfigureAwait(false);
        await healthCheck.VerifyDNSBLWithMode(domainName, DomainIpScanMode.MxAOnly, cancellationToken: cancellationToken).ConfigureAwait(false);

        var assessments = healthCheck.GetAllAssessments().ToArray();
        var overview = Converters.ConvertDomainOverview(
            domainName,
            Converters.Convert(healthCheck.DnsInventoryAnalysis),
            Converters.Convert(healthCheck.SpfAnalysis),
            Converters.Convert(healthCheck.DKIMAnalysis).ToArray(),
            Converters.Convert(healthCheck.DmarcAnalysis),
            Converters.Convert(healthCheck.MXAnalysis),
            Converters.Convert(healthCheck.MTASTSAnalysis),
            Converters.Convert(healthCheck.TLSRPTAnalysis),
            Converters.Convert(healthCheck.BimiAnalysis),
            Converters.Convert(healthCheck.CAAAnalysis),
            Converters.Convert(healthCheck.DaneAnalysis),
            DnsSecConverter.Convert(healthCheck.DnsSecAnalysis),
            Converters.Convert(healthCheck.NSAnalysis),
            Converters.Convert(healthCheck.SOAAnalysis),
            new HttpInfo(),
            new CertificateInfo(),
            new SecurityTxtInfo(),
            new RdapInfo(),
            Converters.Convert(healthCheck.DNSBLAnalysis),
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
}
