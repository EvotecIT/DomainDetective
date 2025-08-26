using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Definitions;
using DnsClientX;

namespace DomainDetective;

/// <summary>
/// Classifies mail domain operational role based on DNS signals.
/// </summary>
/// <remarks>
/// Implements the signals and logic described in the feature request. The
/// classifier leverages existing analyses in <see cref="DomainHealthCheck"/>
/// to avoid duplicate DNS queries.
/// </remarks>
public sealed class MailDomainClassifier {
    private readonly DomainHealthCheck _health;
    private readonly InternalLogger _logger;

    public MailDomainClassifier(DomainHealthCheck health, InternalLogger logger) {
        _health = health ?? throw new ArgumentNullException(nameof(health));
        _logger = logger ?? new InternalLogger(false);
    }

    /// <summary>
    /// Runs required checks and classifies the domain.
    /// </summary>
    /// <param name="domain">Domain name to classify.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<MailDomainClassificationResult> ClassifyAsync(string domain, CancellationToken cancellationToken = default) {
        if (string.IsNullOrWhiteSpace(domain)) {
            throw new ArgumentNullException(nameof(domain));
        }

        // Ensure core signals are collected. Use specific verifications to keep
        // the scope tight and avoid redundant checks.
        await _health.VerifyMX(domain, cancellationToken);
        await _health.VerifySPF(domain, cancellationToken);
        await _health.VerifyDKIM(domain, selectors: Array.Empty<string>(), cancellationToken);
        await _health.VerifyMTASTS(domain, cancellationToken);
        await _health.VerifyTLSRPT(domain, cancellationToken);
        await _health.VerifyBIMI(domain, skipIndicatorDownload: true, cancellationToken);
        await _health.VerifyDANE(domain, new[] { ServiceType.SMTP }, cancellationToken);

        // Apex A/AAAA lookup (SMTP fallback)
        await _health.VerifyApexAddresses(domain, cancellationToken);

        // Compute signals
        var hasNullMx = _health.MXAnalysis?.HasNullMx ?? false;
        var hasMxValid = (_health.MXAnalysis?.MxRecordExists ?? false) && !hasNullMx && !(_health.MXAnalysis?.PointsToLocalhost ?? false);
        var hasAorAAAA = _health.ApexAddressAnalysis?.HasAnyAddress == true;
        var effectiveSpfSends = _health.SpfAnalysis?.EffectiveSpfSends ?? false;
        var hasDkim = _health.DKIMAnalysis?.AnalysisResults?.Values.Any(x => x.DkimRecordExists && x.StartsCorrectly && x.PublicKeyExists && x.ValidPublicKey) == true;
        var hasMtaSts = _health.MTASTSAnalysis?.PolicyValid == true;
        var hasTlsRpt = _health.TLSRPTAnalysis?.TlsRptRecordExists == true;
        var hasDaneSmtp = _health.DaneAnalysis?.AnalysisResults?.Any(x => x.ServiceType == ServiceType.SMTP) == true;
        var hasBimi = _health.BimiAnalysis?.BimiRecordExists == true;

        // Scoring
        var scoreBreakdown = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase) {
            ["HasMX"] = hasMxValid ? 2.0 : 0.0,
            ["HasNullMX"] = hasNullMx ? -5.0 : 0.0, // decisive negative
            ["HasAorAAAA"] = hasAorAAAA ? 0.5 : 0.0,
            ["EffectiveSPFSends"] = effectiveSpfSends ? 2.0 : 0.0,
            ["HasDKIM"] = hasDkim ? 2.0 : 0.0,
            ["HasMTASTS"] = hasMtaSts ? 1.0 : 0.0,
            ["HasTLSRPT"] = hasTlsRpt ? 0.5 : 0.0,
            ["HasDANE"] = hasDaneSmtp ? 0.5 : 0.0,
            ["HasBIMI"] = hasBimi ? 1.0 : 0.0
        };

        double sendingScore = 0.0;
        sendingScore += scoreBreakdown["EffectiveSPFSends"];
        sendingScore += scoreBreakdown["HasDKIM"];
        sendingScore += scoreBreakdown["HasBIMI"];

        double receivingScore = 0.0;
        receivingScore += scoreBreakdown["HasMX"];
        receivingScore += scoreBreakdown["HasMTASTS"];
        receivingScore += scoreBreakdown["HasTLSRPT"];
        receivingScore += scoreBreakdown["HasDANE"];
        receivingScore += scoreBreakdown["HasAorAAAA"];

        var totalScore = scoreBreakdown.Values.Sum();

        // Classification
        var category = MailDomainClassificationCategory.Unknown;
        var reason = "Insufficient signals for confident classification.";
        var confidence = MailDomainClassificationConfidence.Low;

        // Parked: Null MX and no sending signals
        if (hasNullMx && !effectiveSpfSends && !hasDkim && !hasBimi) {
            category = MailDomainClassificationCategory.Parked;
            reason = "Null MX present and no sending authorization signals detected.";
            confidence = MailDomainClassificationConfidence.High;
        } else {
            bool receiving = hasMxValid || hasMtaSts || hasTlsRpt || hasDaneSmtp || hasAorAAAA;
            bool sending = effectiveSpfSends || hasDkim || hasBimi;

            if (receiving && sending) {
                category = MailDomainClassificationCategory.SendingAndReceiving;
                reason = "Domain accepts mail (MX and/or receiving signals) and authorizes sending (SPF/DKIM/BIMI).";
                confidence = (receivingScore >= 2.0 && sendingScore >= 3.0)
                    ? MailDomainClassificationConfidence.High
                    : MailDomainClassificationConfidence.Medium;
            } else if (receiving && !sending) {
                category = MailDomainClassificationCategory.ReceivingOnly;
                reason = "Domain accepts inbound mail but no sending authorization was detected.";
                confidence = MailDomainClassificationConfidence.Medium;
            } else if (!receiving && sending) {
                category = MailDomainClassificationCategory.SendingOnly;
                reason = hasNullMx
                    ? "Domain authorizes sending and explicitly does not accept mail (Null MX)."
                    : "Domain authorizes sending but no MX accepting mail was detected.";
                confidence = hasNullMx ? MailDomainClassificationConfidence.High : MailDomainClassificationConfidence.Medium;
            }
        }

        var receivingSignals = new List<string>();
        if (hasMxValid) receivingSignals.Add("MX");
        if (hasMtaSts) receivingSignals.Add("MTA-STS");
        if (hasTlsRpt) receivingSignals.Add("TLS-RPT");
        if (hasDaneSmtp) receivingSignals.Add("DANE");
        if (!hasMxValid && hasAorAAAA) receivingSignals.Add("A/AAAA");

        var sendingSignals = new List<string>();
        if (effectiveSpfSends) sendingSignals.Add("SPF");
        if (hasDkim) sendingSignals.Add("DKIM");
        if (hasBimi) sendingSignals.Add("BIMI");

        var references = BuildRfcReferences();

        return new MailDomainClassificationResult {
            Domain = domain,
            Classification = category,
            Confidence = confidence,
            Signals = new MailDomainSignalSummary {
                HasMX = hasMxValid,
                HasNullMX = hasNullMx,
                HasAorAAAA = hasAorAAAA,
                EffectiveSpfSends = effectiveSpfSends,
                HasDKIM = hasDkim,
                HasMTASTS = hasMtaSts,
                HasTLSRPT = hasTlsRpt,
                HasDANE = hasDaneSmtp,
                HasBIMI = hasBimi
            },
            ClassificationReason = reason,
            ReceivingSignals = receivingSignals,
            SendingSignals = sendingSignals,
            SPFIncludesResolved = _health.SpfAnalysis?.ResolvedIncludeRecords?.Distinct(StringComparer.OrdinalIgnoreCase).ToList() ?? new List<string>(),
            DKIMSelectorsFound = _health.DKIMAnalysis?.AnalysisResults?.Keys?.ToList() ?? new List<string>(),
            Score = totalScore,
            ScoreBreakdown = scoreBreakdown,
            RfcReferences = references
        };
    }

    private IReadOnlyList<StandardReference> BuildRfcReferences() {
        var list = new List<StandardReference>();
        void AddRange(IEnumerable<StandardReference> refsList) {
            if (refsList == null) return;
            foreach (var r in refsList) {
                if (!list.Any(x => string.Equals(x.Reference, r.Reference, StringComparison.OrdinalIgnoreCase))) {
                    list.Add(r);
                }
            }
        }
        AddRange(_health.SpfAnalysis?.RfcReferences);
        AddRange(_health.DKIMAnalysis?.RfcReferences);
        AddRange(_health.MXAnalysis?.RfcReferences);
        AddRange(_health.MTASTSAnalysis?.RfcReferences);
        AddRange(_health.TLSRPTAnalysis?.RfcReferences);
        AddRange(_health.DaneAnalysis?.RfcReferences);
        AddRange(_health.BimiAnalysis?.RfcReferences);
        return list;
    }
}
