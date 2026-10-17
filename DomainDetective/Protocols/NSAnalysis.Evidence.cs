using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class NSAnalysis {
    private readonly List<string> _childDnsQueryErrors = new();
    private readonly List<string> _delegationDnsQueryErrors = new();

    /// <summary>True when child NS discovery returned a conclusive DNS response or supplied records were analyzed.</summary>
    public bool NsLookupComplete { get; private set; }
    /// <summary>True when parent delegation and applicable glue comparisons were checked without query failures.</summary>
    public bool DelegationAnalysisComplete { get; private set; }
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
        NsRecords = new();
        ParentNsRecords = new();
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
        || error is TimeoutException || error is TaskCanceledException || error is System.Net.Http.HttpRequestException;

    private async Task<(DnsAnswer[] Answers, Exception? Error)> QueryNsEvidenceAsync(string name, DnsRecordType type, CancellationToken ct) {
        try { return (await QueryDns(name, type, ct).ConfigureAwait(false), null); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error) when (IsDnsQueryFailure(error)) { return (Array.Empty<DnsAnswer>(), error); }
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
}
