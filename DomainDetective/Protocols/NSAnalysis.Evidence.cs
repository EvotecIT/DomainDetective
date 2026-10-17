using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class NSAnalysis {
    private List<string> _childDnsQueryErrors = new();
    private List<string> _delegationDnsQueryErrors = new();

    /// <summary>True when child NS discovery returned a conclusive DNS response or supplied records were analyzed.</summary>
    public bool NsLookupComplete { get; private set; }
    /// <summary>True when parent delegation and applicable glue comparisons completed; unused discovery failures remain diagnostic.</summary>
    public bool DelegationAnalysisComplete { get; private set; }
    /// <summary>True when an observed parent delegation establishes whether required glue is present.</summary>
    public bool GluePresenceKnown => ParentNsRecords.Count > 0;
    /// <summary>True when a glue mismatch is confirmed, or every required glue comparison confirms consistency.</summary>
    public bool GlueConsistencyKnown { get; private set; }
    /// <summary>True when DNS failures affect child NS discovery or child-host enrichment.</summary>
    public bool ChildDnsQueryFailed => _childDnsQueryErrors.Count > 0;
    /// <summary>True when every NS has an observed address, or at least one NS is confirmed to have none.</summary>
    public bool AddressResultKnown { get; private set; }
    /// <summary>True when a CNAME target is observed or every child CNAME query completed.</summary>
    public bool CnameResultKnown { get; private set; }
    /// <summary>True when diversity is observed or all address and ASN evidence needed to exclude it is available.</summary>
    public bool DiversityResultKnown { get; private set; }
    /// <summary>True when all child address queries and ASN lookups completed; otherwise the ASN count is a lower bound.</summary>
    public bool AsnDiversityComplete { get; private set; }
    /// <summary>True when DNS failures leave child discovery, address enrichment or delegation evidence incomplete.</summary>
    public bool DnsQueryFailed => _childDnsQueryErrors.Count > 0 || _delegationDnsQueryErrors.Count > 0;
    /// <summary>Operational failures retained separately from confirmed missing records or mismatched glue.</summary>
    public IReadOnlyList<string> DnsQueryErrors => _childDnsQueryErrors.Concat(_delegationDnsQueryErrors).ToArray();

    /// <summary>Starts fresh child evidence while preserving configuration and the selected subject.</summary>
    internal void ResetNsEvidence() {
        Assessments.Clear();
        _childDnsQueryErrors.Clear();
        _delegationDnsQueryErrors.Clear();
        NsLookupComplete = DelegationAnalysisComplete = false;
        GlueConsistencyKnown = false;
        AddressResultKnown = CnameResultKnown = DiversityResultKnown = AsnDiversityComplete = false;
        NsRecords = new();
        ParentNsRecords = new();
        ParentAuthorityServer = null;
        NsRecordExists = HasDuplicates = AtLeastTwoRecords = AllHaveAOrAaaa = false;
        PointsToCname = HasDiverseLocations = DelegationMatches = false;
        GlueRecordsComplete = GlueRecordsConsistent = false;
        RootServerResponses = new();
        RecursionEnabled = new();
        ChaosVersionByServer = new(StringComparer.OrdinalIgnoreCase);
        ChaosHostnameByServer = new(StringComparer.OrdinalIgnoreCase);
        AsnByIp = new(StringComparer.OrdinalIgnoreCase);
        AsnDistinctCount = 0;
    }

    internal static bool IsDnsQueryFailure(Exception error) => error is DnsQueryFailureException
        || Helpers.AuthoritativeDnsProbes.IsTransportFailure(error);

    private async Task<(DnsAnswer[] Answers, Exception? Error)> QueryNsEvidenceAsync(string name, DnsRecordType type, CancellationToken ct) {
        try { return (await QueryDns(name, type, ct).ConfigureAwait(false), null); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error) when (IsDnsQueryFailure(error)) {
            ct.ThrowIfCancellationRequested();
            return (Array.Empty<DnsAnswer>(), error);
        }
    }

    private void RecordQueryError(string name, DnsRecordType type, Exception? error, InternalLogger logger, bool parent = false) {
        if (error != null) { RecordDnsQueryFailure(name, type, error, logger, parent); }
    }

    /// <summary>Records failure after bounded workers finish; the caller's phase collector captures the notification.</summary>
    internal void RecordDnsQueryFailure(string name, DnsRecordType type, Exception error, InternalLogger logger, bool parent = false) {
        string detail = $"{name} ({type}): {error.Message}";
        (parent ? _delegationDnsQueryErrors : _childDnsQueryErrors).Add(detail);
        logger.WriteWarningCode(NSCodes.QueryFailed, "NS DNS query failed for {0}", detail);
    }

    /// <summary>Copies observed evidence without sharing mutable result containers with a later refresh.</summary>
    internal NSAnalysis CloneForSnapshot() {
        var clone = (NSAnalysis)MemberwiseClone();
        clone._childDnsQueryErrors = new(_childDnsQueryErrors);
        clone._delegationDnsQueryErrors = new(_delegationDnsQueryErrors);
        clone.NsRecords = new(NsRecords);
        clone.ParentNsRecords = new(ParentNsRecords);
        clone.RootServerResponses = new(RootServerResponses);
        clone.RecursionEnabled = new(RecursionEnabled);
        clone.ChaosVersionByServer = new(ChaosVersionByServer, StringComparer.OrdinalIgnoreCase);
        clone.ChaosHostnameByServer = new(ChaosHostnameByServer, StringComparer.OrdinalIgnoreCase);
        clone.AsnByIp = new(AsnByIp, StringComparer.OrdinalIgnoreCase);
        clone.Assessments = Assessments.Select(item => new Assessment {
            Severity = item.Severity, Message = item.Message, Code = item.Code, Category = item.Category,
            Target = item.Target, Source = item.Source, Timestamp = item.Timestamp,
            Metadata = new Dictionary<string, string>(item.Metadata, item.Metadata.Comparer)
        }).ToList();
        return clone;
    }
}
