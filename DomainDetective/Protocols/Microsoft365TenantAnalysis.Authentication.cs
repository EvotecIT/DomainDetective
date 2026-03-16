using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Helpers;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public sealed partial class Microsoft365TenantAnalysis {
    /// <summary>
    /// Performs a best-effort public Microsoft authentication surface probe for the domain.
    /// </summary>
    public async Task ProbeAuthenticationAsync(
        string domain,
        IHttpClientFactory? httpClientFactory = null,
        InternalLogger? logger = null,
        CancellationToken cancellationToken = default) {
        if (string.IsNullOrWhiteSpace(domain)) {
            throw new ArgumentNullException(nameof(domain));
        }

        domain = DomainHelper.ValidateIdn(domain);
        RemoveAuthenticationSummaryAssessments();
        UserEnumerationStatus = Microsoft365AuthExposureStatus.Unknown;
        SmartLockoutStatus = Microsoft365AuthExposureStatus.Unknown;

        // The public GetCredentialType endpoint behaves like an interactive browser flow and returns
        // the most useful tenant-routing information when the probe resembles a normal sign-in request.
        var probeAddress = AuthenticationProbePrefix + Guid.NewGuid().ToString("N") + "@" + domain;
        var probe = await MicrosoftIdentityProbeClient.TryGetCredentialTypeAsync(
            probeAddress,
            httpClientFactory,
            cancellationToken).ConfigureAwait(false);
        if (probe == null) {
            return;
        }

        AuthenticationProbeSucceeded = true;
        AuthenticationProbeAddress = probeAddress;
        AuthenticationProbe = probe;
        UserEnumerationStatus = MapUserEnumerationStatus(probe);
        SmartLockoutStatus = MapSmartLockoutStatus(probe);

        if (!IsMicrosoft365Tenant && IsAuthenticationProbeMicrosoft365Signal(probe)) {
            IsMicrosoft365Tenant = true;
            if (DetectionConfidence < Microsoft365DetectionConfidence.Moderate) {
                DetectionConfidence = Microsoft365DetectionConfidence.Moderate;
            }
            RemoveAssessmentByCode(Microsoft365Codes.NotDetected);
        }

        if (UserEnumerationStatus == Microsoft365AuthExposureStatus.Exposed) {
            Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "Microsoft 365",
                Code = Microsoft365Codes.AuthUserEnumerationExposed,
                Target = Subject ?? domain,
                Message = $"Public Microsoft auth probe indicates user-enumeration style response for {domain} (IfExistsResult={FormatProbeValue(probe.IfExistsResult)})."
            });
        }

        Assessments.Add(new Assessment {
            Severity = AssessmentSeverity.Info,
            Category = "Microsoft 365",
            Code = Microsoft365Codes.AuthProbeDetected,
            Target = Subject ?? domain,
            Message = $"Microsoft auth surface probe returned IfExistsResult={FormatProbeValue(probe.IfExistsResult)}, ThrottleStatus={FormatProbeValue(probe.ThrottleStatus)}, DomainType={FormatProbeValue(probe.DomainType)}."
        });

        AuthenticationSummary = BuildAuthenticationSummary(probeAddress, probe);
        AddAuthenticationSummaryAssessments(domain, AuthenticationSummary);
        AddAuthenticationEvidence(probeAddress, probe);

        logger?.WriteVerbose(
            "Microsoft auth probe for {0}: IfExistsResult={1}, ThrottleStatus={2}, DomainType={3}",
            domain,
            FormatProbeValue(probe.IfExistsResult),
            FormatProbeValue(probe.ThrottleStatus),
            FormatProbeValue(probe.DomainType));
    }

    private static string FormatProbeValue(int? value) {
        return value.HasValue ? value.Value.ToString() : "-";
    }

    private Microsoft365AuthenticationSummary BuildAuthenticationSummary(string? probeAddress, MicrosoftCredentialTypeProbe? probe) {
        return new Microsoft365AuthenticationSummary {
            ProbeResponsive = probe != null,
            UserEnumerationStatus = UserEnumerationStatus,
            SmartLockoutStatus = SmartLockoutStatus,
            IfExistsResult = probe?.IfExistsResult,
            ThrottleStatus = probe?.ThrottleStatus,
            DomainType = probe?.DomainType,
            PreferredCredential = probe?.PreferredCredential,
            FederationRedirectUrl = probe?.FederationRedirectUrl,
            DomainPosture = GetAuthenticationDomainPosture(probe),
            CredentialFlow = GetAuthenticationCredentialFlow(probe),
            AuthenticationPath = GetAuthenticationPath(probe),
            Confidence = probe == null ? Microsoft365DetectionConfidence.Unknown : Microsoft365DetectionConfidence.Strong,
            Evidence = BuildAuthenticationEvidence(probeAddress, probe)
        };
    }

    private Microsoft365AuthDomainPostureKind GetAuthenticationDomainPosture(MicrosoftCredentialTypeProbe? probe) {
        if (probe == null) {
            return Microsoft365AuthDomainPostureKind.Unknown;
        }

        if (ConsumerDomain) {
            return Microsoft365AuthDomainPostureKind.ConsumerTenant;
        }

        if (FederationMode == Microsoft365FederationMode.Federated ||
            string.Equals(NameSpaceType, "Federated", StringComparison.OrdinalIgnoreCase)) {
            return Microsoft365AuthDomainPostureKind.FederatedTenant;
        }

        if (FederationMode == Microsoft365FederationMode.CloudManaged ||
            string.Equals(NameSpaceType, "Managed", StringComparison.OrdinalIgnoreCase) ||
            probe.DomainType == 3) {
            return Microsoft365AuthDomainPostureKind.ManagedTenant;
        }

        return Microsoft365AuthDomainPostureKind.Unknown;
    }

    private static Microsoft365AuthCredentialFlowKind GetAuthenticationCredentialFlow(MicrosoftCredentialTypeProbe? probe) {
        if (probe == null) {
            return Microsoft365AuthCredentialFlowKind.Unknown;
        }

        if (!string.IsNullOrWhiteSpace(probe.FederationRedirectUrl)) {
            return Microsoft365AuthCredentialFlowKind.Redirect;
        }

        if (probe.PreferredCredential.HasValue) {
            return Microsoft365AuthCredentialFlowKind.NativeCredential;
        }

        return Microsoft365AuthCredentialFlowKind.Unknown;
    }

    private Microsoft365AuthPathKind GetAuthenticationPath(MicrosoftCredentialTypeProbe? probe) {
        if (probe == null) {
            return Microsoft365AuthPathKind.Unknown;
        }

        var posture = GetAuthenticationDomainPosture(probe);
        var flow = GetAuthenticationCredentialFlow(probe);

        if (posture == Microsoft365AuthDomainPostureKind.ManagedTenant && flow == Microsoft365AuthCredentialFlowKind.NativeCredential) {
            return Microsoft365AuthPathKind.ManagedNative;
        }

        if (posture == Microsoft365AuthDomainPostureKind.ManagedTenant && flow == Microsoft365AuthCredentialFlowKind.Redirect) {
            return Microsoft365AuthPathKind.ManagedRedirect;
        }

        if (posture == Microsoft365AuthDomainPostureKind.FederatedTenant && flow == Microsoft365AuthCredentialFlowKind.Redirect) {
            return Microsoft365AuthPathKind.FederatedRedirect;
        }

        if (posture == Microsoft365AuthDomainPostureKind.FederatedTenant) {
            return Microsoft365AuthPathKind.Federated;
        }

        if (posture == Microsoft365AuthDomainPostureKind.ConsumerTenant) {
            return Microsoft365AuthPathKind.ConsumerIdentity;
        }

        if (flow == Microsoft365AuthCredentialFlowKind.Redirect) {
            return Microsoft365AuthPathKind.Redirect;
        }

        if (flow == Microsoft365AuthCredentialFlowKind.NativeCredential) {
            return Microsoft365AuthPathKind.NativeCredential;
        }

        return Microsoft365AuthPathKind.Unknown;
    }

    private static IReadOnlyList<string> BuildAuthenticationEvidence(string? probeAddress, MicrosoftCredentialTypeProbe? probe) {
        if (probe == null) {
            return Array.Empty<string>();
        }

        var evidence = new List<string>();
        if (!string.IsNullOrWhiteSpace(probeAddress)) {
            evidence.Add("Probe: " + probeAddress);
        }

        evidence.Add("IfExistsResult=" + FormatProbeValue(probe.IfExistsResult));
        evidence.Add("ThrottleStatus=" + FormatProbeValue(probe.ThrottleStatus));
        evidence.Add("DomainType=" + FormatProbeValue(probe.DomainType));
        evidence.Add("PreferredCredential=" + FormatProbeValue(probe.PreferredCredential));

        var redirectHost = TryGetFederationRedirectHost(probe.FederationRedirectUrl);
        if (!string.IsNullOrWhiteSpace(redirectHost)) {
            evidence.Add("FederationRedirectHost=" + redirectHost);
        }

        return evidence;
    }

    private void AddAuthenticationSummaryAssessments(string domain, Microsoft365AuthenticationSummary summary) {
        if (!summary.ProbeResponsive) {
            return;
        }

        var target = Subject ?? domain;
        switch (summary.DomainPosture) {
            case Microsoft365AuthDomainPostureKind.ManagedTenant:
                Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Info,
                    Category = "Microsoft 365",
                    Code = Microsoft365Codes.AuthManagedPostureDetected,
                    Target = target,
                    Message = $"Microsoft auth probe posture for {domain} is consistent with a managed tenant."
                });
                break;
            case Microsoft365AuthDomainPostureKind.FederatedTenant:
                Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Info,
                    Category = "Microsoft 365",
                    Code = Microsoft365Codes.AuthFederatedPostureDetected,
                    Target = target,
                    Message = $"Microsoft auth probe posture for {domain} is consistent with a federated tenant."
                });
                break;
            case Microsoft365AuthDomainPostureKind.ConsumerTenant:
                Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Info,
                    Category = "Microsoft 365",
                    Code = Microsoft365Codes.AuthConsumerPostureDetected,
                    Target = target,
                    Message = $"Microsoft auth probe posture for {domain} is consistent with a consumer tenant."
                });
                break;
        }

        switch (summary.CredentialFlow) {
            case Microsoft365AuthCredentialFlowKind.Redirect:
                Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Info,
                    Category = "Microsoft 365",
                    Code = Microsoft365Codes.AuthRedirectFlowDetected,
                    Target = target,
                    Message = $"Microsoft auth probe indicates a redirect-based sign-in flow for {domain}."
                });
                break;
            case Microsoft365AuthCredentialFlowKind.NativeCredential:
                Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Info,
                    Category = "Microsoft 365",
                    Code = Microsoft365Codes.AuthNativeCredentialFlowDetected,
                    Target = target,
                    Message = $"Microsoft auth probe indicates a native credential sign-in flow for {domain}."
                });
                break;
        }

        switch (summary.DomainPosture) {
            case Microsoft365AuthDomainPostureKind.FederatedTenant when summary.CredentialFlow == Microsoft365AuthCredentialFlowKind.Redirect:
                Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Info,
                    Category = "Microsoft 365",
                    Code = Microsoft365Codes.AuthFederatedRedirectPathDetected,
                    Target = target,
                    Message = $"Microsoft auth probe indicates a federated redirect sign-in path for {domain}."
                });
                break;
            case Microsoft365AuthDomainPostureKind.ManagedTenant when summary.CredentialFlow == Microsoft365AuthCredentialFlowKind.Redirect:
                Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Info,
                    Category = "Microsoft 365",
                    Code = Microsoft365Codes.AuthManagedRedirectPathDetected,
                    Target = target,
                    Message = $"Microsoft auth probe indicates a managed tenant with a redirect-based sign-in path for {domain}."
                });
                break;
            case Microsoft365AuthDomainPostureKind.ManagedTenant when summary.CredentialFlow == Microsoft365AuthCredentialFlowKind.NativeCredential:
                Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Info,
                    Category = "Microsoft 365",
                    Code = Microsoft365Codes.AuthManagedNativePathDetected,
                    Target = target,
                    Message = $"Microsoft auth probe indicates a managed tenant with a native credential sign-in path for {domain}."
                });
                break;
        }
    }

    private void RemoveAuthenticationSummaryAssessments() {
        for (var i = Assessments.Count - 1; i >= 0; i--) {
            var code = Assessments[i].Code;
            if (string.Equals(code, Microsoft365Codes.AuthManagedPostureDetected, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(code, Microsoft365Codes.AuthProbeDetected, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(code, Microsoft365Codes.AuthUserEnumerationExposed, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(code, Microsoft365Codes.AuthFederatedPostureDetected, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(code, Microsoft365Codes.AuthConsumerPostureDetected, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(code, Microsoft365Codes.AuthRedirectFlowDetected, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(code, Microsoft365Codes.AuthNativeCredentialFlowDetected, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(code, Microsoft365Codes.AuthFederatedRedirectPathDetected, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(code, Microsoft365Codes.AuthManagedRedirectPathDetected, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(code, Microsoft365Codes.AuthManagedNativePathDetected, StringComparison.OrdinalIgnoreCase)) {
                Assessments.RemoveAt(i);
            }
        }
    }

    private void AddAuthenticationEvidence(string probeAddress, MicrosoftCredentialTypeProbe probe) {
        var item = new Microsoft365EvidenceItem {
            Id = "auth-getcredentialtype",
            Label = "Authentication probe",
            Category = Microsoft365EvidenceCategory.Authentication,
            Confidence = Microsoft365DetectionConfidence.Strong,
            Evidence = BuildAuthenticationEvidence(probeAddress, probe)
        };

        EvidenceLedger = new[] { item }
            .Concat(EvidenceLedger ?? Array.Empty<Microsoft365EvidenceItem>())
            .GroupBy(static entry => entry.Id, StringComparer.OrdinalIgnoreCase)
            .Select(static group => group.First())
            .OrderByDescending(static entry => entry.Confidence)
            .ThenBy(static entry => entry.Category)
            .ThenBy(static entry => entry.Label, StringComparer.OrdinalIgnoreCase)
            .Take(EvidenceLedgerMaxItems)
            .ToList();
        EvidenceSummary = BuildEvidenceSummary(EvidenceLedger);
    }

    private static Microsoft365AuthExposureStatus MapUserEnumerationStatus(MicrosoftCredentialTypeProbe probe) {
        if (!probe.IfExistsResult.HasValue) {
            return Microsoft365AuthExposureStatus.Unknown;
        }

        return probe.IfExistsResult.Value switch {
            0 => Microsoft365AuthExposureStatus.Exposed,
            1 => Microsoft365AuthExposureStatus.Exposed,
            5 => Microsoft365AuthExposureStatus.Unknown,
            6 => Microsoft365AuthExposureStatus.Unknown,
            _ => Microsoft365AuthExposureStatus.Unknown
        };
    }

    private static Microsoft365AuthExposureStatus MapSmartLockoutStatus(MicrosoftCredentialTypeProbe probe) {
        return Microsoft365AuthExposureStatus.Unknown;
    }

    private static bool IsAuthenticationProbeMicrosoft365Signal(MicrosoftCredentialTypeProbe probe) {
        return probe.DomainType.HasValue ||
               probe.PreferredCredential.HasValue ||
               !string.IsNullOrWhiteSpace(probe.FederationRedirectUrl);
    }

    private static string? TryGetFederationRedirectHost(string? federationRedirectUrl) {
        if (string.IsNullOrWhiteSpace(federationRedirectUrl)) {
            return null;
        }

        if (!Uri.TryCreate(federationRedirectUrl, UriKind.Absolute, out var uri)) {
            return null;
        }

        return uri.Host;
    }

    private void RemoveAssessmentByCode(string code) {
        for (var i = Assessments.Count - 1; i >= 0; i--) {
            if (string.Equals(Assessments[i].Code, code, StringComparison.OrdinalIgnoreCase)) {
                Assessments.RemoveAt(i);
            }
        }
    }
}
