using DomainDetective.Providers.Email;
using DomainDetective.Providers.Dns;
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
        overview.UnavailableSections = BuildBrowserMicrosoft365UnavailableSections(tenant);
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
        var microsoftApps = dnsInventory.DetectedDnsApplications
            .Where(IsMicrosoft365Application)
            .ToArray();
        var hasMicrosoftMail = dnsInventory.MailProvider == MailProviderKind.Microsoft365;
        var hasMicrosoftVerification = dnsInventory.TxtSignals.HasFlag(DnsTxtSignals.MicrosoftDomainVerification);
        var isMicrosoft365Observed = hasMicrosoftMail || hasMicrosoftVerification || microsoftApps.Length > 0;
        var confidence = BuildBrowserTenantConfidence(hasMicrosoftMail, hasMicrosoftVerification, microsoftApps);
        var services = BuildBrowserServiceDetections(hasMicrosoftMail, dnsInventory.MailProviderEvidence);
        var tenantDomains = BuildBrowserTenantDomains(domainName, isMicrosoft365Observed, confidence, dnsInventory);
        var evidenceLedger = BuildBrowserEvidenceLedger(dnsInventory, hasMicrosoftMail, hasMicrosoftVerification, microsoftApps);
        var highlights = new List<string>();
        if (hasMicrosoftMail) {
            highlights.Add("Microsoft 365 mail routing observed from MX evidence.");
        } else if (dnsInventory.MailProvider != MailProviderKind.Unknown) {
            highlights.Add("Mail provider hint: " + dnsInventory.MailProvider);
        }

        if (hasMicrosoftVerification) {
            highlights.Add("Microsoft domain verification TXT evidence observed.");
        }

        if (dnsInventory.DetectedDnsApplications.Count > 0) {
            highlights.Add($"Detected {dnsInventory.DetectedDnsApplications.Count} DNS application hint(s).");
        }

        highlights.Add("Web edition: identity, tenant, and auth probing require the deeper online run.");

        return new Microsoft365TenantInfo {
            Subject = domainName,
            QuerySucceeded = dnsInventory.QuerySucceeded,
            IsMicrosoft365Tenant = isMicrosoft365Observed,
            DetectionConfidence = confidence,
            TenantName = domainName,
            TenantDomains = tenantDomains,
            Services = services,
            WorkloadSummary = BuildBrowserWorkloadSummary(services),
            DnsApplicationSummary = BuildBrowserDnsApplicationSummary(dnsInventory.DetectedDnsApplications),
            EvidenceSummary = BuildBrowserEvidenceSummary(evidenceLedger),
            DetectedDnsApplications = dnsInventory.DetectedDnsApplications,
            EvidenceLedger = evidenceLedger,
            Highlights = highlights,
            Summary = isMicrosoft365Observed
                ? "Web edition Microsoft 365 overview built from observed DNS, mail, and application evidence. Tenant identity and auth posture need the deeper online run."
                : "Web edition Microsoft 365 overview built from public DNS and mail posture only. Tenant identity and auth posture need the deeper online run."
        };
    }

    private static IReadOnlyList<string> BuildBrowserMicrosoft365UnavailableSections(Microsoft365TenantInfo tenant) {
        var sections = new List<string> {
            "Identity"
        };

        if (tenant.Services.Count == 0) {
            sections.Add("Services");
        }

        if (tenant.TenantDomains.Count == 0 && tenant.KnownSubdomains.Count == 0) {
            sections.Add("Domains");
        }

        return sections;
    }

    private static bool IsMicrosoft365Application(DetectedDnsApplication app) {
        return string.Equals(app.Id, "mail-provider-microsoft365", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(app.Id, "microsoft-365", StringComparison.OrdinalIgnoreCase) ||
            app.Name.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
            app.Name.Contains("Office 365", StringComparison.OrdinalIgnoreCase);
    }

    private static Microsoft365DetectionConfidence BuildBrowserTenantConfidence(bool hasMicrosoftMail, bool hasMicrosoftVerification, IReadOnlyList<DetectedDnsApplication> microsoftApps) {
        if (hasMicrosoftMail || hasMicrosoftVerification ||
            microsoftApps.Any(static app => app.Confidence == Microsoft365DetectionConfidence.Strong)) {
            return Microsoft365DetectionConfidence.Strong;
        }

        if (microsoftApps.Any(static app => app.Confidence == Microsoft365DetectionConfidence.Moderate)) {
            return Microsoft365DetectionConfidence.Moderate;
        }

        if (microsoftApps.Any(static app => app.Confidence == Microsoft365DetectionConfidence.Weak)) {
            return Microsoft365DetectionConfidence.Weak;
        }

        return Microsoft365DetectionConfidence.Unknown;
    }

    private static IReadOnlyList<Microsoft365ServiceDetection> BuildBrowserServiceDetections(bool hasMicrosoftMail, IReadOnlyList<string> mailProviderEvidence) {
        if (!hasMicrosoftMail) {
            return Array.Empty<Microsoft365ServiceDetection>();
        }

        return new[] {
            new Microsoft365ServiceDetection {
                Kind = Microsoft365ServiceKind.ExchangeOnline,
                Status = Microsoft365DetectionStatus.Detected,
                Confidence = Microsoft365DetectionConfidence.Strong,
                EvidenceSource = Microsoft365ServiceEvidenceSourceKind.MailProtocol,
                Evidence = mailProviderEvidence.Count > 0
                    ? mailProviderEvidence
                    : new[] { "Mail provider: Microsoft 365" }
            }
        };
    }

    private static IReadOnlyList<Microsoft365TenantDomain> BuildBrowserTenantDomains(string domainName, bool isMicrosoft365Observed, Microsoft365DetectionConfidence confidence, DnsInventoryInfo dnsInventory) {
        if (!isMicrosoft365Observed) {
            return Array.Empty<Microsoft365TenantDomain>();
        }

        var evidence = new List<string>();
        evidence.AddRange(dnsInventory.MailProviderEvidence.Where(static item => !string.IsNullOrWhiteSpace(item)).Take(3));
        evidence.AddRange(dnsInventory.TxtSignalsEvidence.Where(static item => !string.IsNullOrWhiteSpace(item)).Take(2));

        if (evidence.Count == 0) {
            evidence.Add("Browser-safe DNS and mail evidence observed.");
        }

        return new[] {
            new Microsoft365TenantDomain {
                Domain = domainName,
                Role = Microsoft365TenantDomainRole.AcceptedCustomDomain,
                Confidence = confidence == Microsoft365DetectionConfidence.Unknown ? Microsoft365DetectionConfidence.Weak : confidence,
                Evidence = evidence
            }
        };
    }

    private static IReadOnlyList<Microsoft365EvidenceItem> BuildBrowserEvidenceLedger(
        DnsInventoryInfo dnsInventory,
        bool hasMicrosoftMail,
        bool hasMicrosoftVerification,
        IReadOnlyList<DetectedDnsApplication> microsoftApps) {
        var items = new List<Microsoft365EvidenceItem>();

        if (hasMicrosoftMail) {
            items.Add(new Microsoft365EvidenceItem {
                Id = "browser-mail-provider-microsoft365",
                Label = "Microsoft 365 mail provider",
                Category = Microsoft365EvidenceCategory.Mail,
                Confidence = Microsoft365DetectionConfidence.Strong,
                Evidence = dnsInventory.MailProviderEvidence.Count > 0
                    ? dnsInventory.MailProviderEvidence
                    : new[] { "Mail provider: Microsoft 365" }
            });
        }

        if (hasMicrosoftVerification) {
            items.Add(new Microsoft365EvidenceItem {
                Id = "browser-txt-microsoft-verification",
                Label = "Microsoft TXT verification",
                Category = Microsoft365EvidenceCategory.DnsApplication,
                Confidence = Microsoft365DetectionConfidence.Strong,
                Evidence = dnsInventory.TxtSignalsEvidence.Count > 0
                    ? dnsInventory.TxtSignalsEvidence
                    : new[] { "Microsoft domain verification TXT signal" }
            });
        }

        foreach (var app in microsoftApps) {
            items.Add(new Microsoft365EvidenceItem {
                Id = "browser-app-" + app.Id,
                Label = app.Name,
                Category = Microsoft365EvidenceCategory.DnsApplication,
                Confidence = app.Confidence,
                Evidence = string.IsNullOrWhiteSpace(app.Evidence)
                    ? Array.Empty<string>()
                    : new[] { app.Evidence }
            });
        }

        return items
            .GroupBy(static item => item.Id, StringComparer.OrdinalIgnoreCase)
            .Select(static group => group.First())
            .ToArray();
    }

    private static Microsoft365WorkloadConfidenceSummary BuildBrowserWorkloadSummary(IReadOnlyList<Microsoft365ServiceDetection> services) {
        return new Microsoft365WorkloadConfidenceSummary {
            DetectedCount = services.Count(static service => service.Status == Microsoft365DetectionStatus.Detected),
            StrongCount = services.Count(static service => service.Status == Microsoft365DetectionStatus.Detected && service.Confidence == Microsoft365DetectionConfidence.Strong),
            ModerateCount = services.Count(static service => service.Status == Microsoft365DetectionStatus.Detected && service.Confidence == Microsoft365DetectionConfidence.Moderate),
            WeakCount = services.Count(static service => service.Status == Microsoft365DetectionStatus.Detected && service.Confidence == Microsoft365DetectionConfidence.Weak),
            StrongServices = services
                .Where(static service => service.Status == Microsoft365DetectionStatus.Detected && service.Confidence == Microsoft365DetectionConfidence.Strong)
                .Select(static service => service.Kind)
                .ToArray(),
            ModerateServices = services
                .Where(static service => service.Status == Microsoft365DetectionStatus.Detected && service.Confidence == Microsoft365DetectionConfidence.Moderate)
                .Select(static service => service.Kind)
                .ToArray(),
            WeakServices = services
                .Where(static service => service.Status == Microsoft365DetectionStatus.Detected && service.Confidence == Microsoft365DetectionConfidence.Weak)
                .Select(static service => service.Kind)
                .ToArray()
        };
    }

    private static Microsoft365DnsApplicationSummary BuildBrowserDnsApplicationSummary(IReadOnlyList<DetectedDnsApplication> applications) {
        var categories = applications
            .GroupBy(static app => app.Category)
            .Select(static group => new Microsoft365DnsApplicationCategorySummary {
                Category = group.Key,
                Count = group.Count(),
                HighestConfidence = group.Max(static app => app.Confidence),
                ApplicationNames = group
                    .Select(static app => app.Name)
                    .Where(static name => !string.IsNullOrWhiteSpace(name))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(6)
                    .ToArray()
            })
            .OrderByDescending(static category => category.Count)
            .ThenBy(static category => category.Category)
            .ToArray();
        var dominantCategory = categories.FirstOrDefault();

        return new Microsoft365DnsApplicationSummary {
            TotalCount = applications.Count,
            CategoryCount = categories.Length,
            DominantCategory = dominantCategory?.Category ?? DetectedDnsAppCategory.Unknown,
            DominantCategoryCount = dominantCategory?.Count ?? 0,
            Categories = categories
        };
    }

    private static Microsoft365EvidenceSummary BuildBrowserEvidenceSummary(IReadOnlyList<Microsoft365EvidenceItem> evidence) {
        var categories = evidence
            .GroupBy(static item => item.Category)
            .Select(static group => new Microsoft365EvidenceCategorySummary {
                Category = group.Key,
                Count = group.Count(),
                HighestConfidence = group.Max(static item => item.Confidence),
                Labels = group
                    .Select(static item => item.Label)
                    .Where(static label => !string.IsNullOrWhiteSpace(label))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(6)
                    .ToArray()
            })
            .OrderByDescending(static category => category.Count)
            .ThenBy(static category => category.Category)
            .ToArray();
        var dominantCategory = categories.FirstOrDefault();

        return new Microsoft365EvidenceSummary {
            TotalCount = evidence.Count,
            CategoryCount = categories.Length,
            DominantCategory = dominantCategory?.Category ?? Microsoft365EvidenceCategory.Unknown,
            DominantCategoryCount = dominantCategory?.Count ?? 0,
            Categories = categories
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
