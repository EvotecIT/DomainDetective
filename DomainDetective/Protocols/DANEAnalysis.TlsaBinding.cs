using DnsClientX;
using System;
using System.Linq;

namespace DomainDetective;

public partial class DANEAnalysis {
    // A TLSA RRset can use a CNAME/DNAME target, but unrelated same-type answers
    // must never change the service whose certificate is being authenticated.
    internal static DnsAnswer[] BindServiceTlsaAnswers(string serviceOwner, DnsResponse? response) {
        if (response == null || response.Status != DnsResponseCode.NoError || !string.IsNullOrEmpty(response.Error))
            return Array.Empty<DnsAnswer>();

        DnsAnswer[] answers = (response.Answers ?? Array.Empty<DnsAnswer>())
            .Where(answer => answer.Type == DnsRecordType.TLSA && !string.IsNullOrWhiteSpace(answer.Name))
            .ToArray();
        DnsAnswer[] direct = answers.Where(answer => SameOwner(answer.Name, serviceOwner)).ToArray();
        if (direct.Length > 0)
            return direct.Select(answer => WithServiceOwner(answer, serviceOwner)).ToArray();

        // DnsClientX establishes this flag from the complete answer and its
        // alias chain before projecting CNAME/DNAME records out of a TLSA query.
        if (!response.RequestedAnswerPresent || answers.Length == 0 ||
            answers.Select(answer => answer.Name.TrimEnd('.')).Distinct(StringComparer.OrdinalIgnoreCase).Count() != 1)
            return Array.Empty<DnsAnswer>();

        return answers.Select(answer => WithServiceOwner(answer, serviceOwner)).ToArray();
    }

    internal static DnsAnswer[] BindServiceTlsaAnswers(string serviceOwner, DnsAnswer[]? answers) {
        return (answers ?? Array.Empty<DnsAnswer>())
            .Where(answer => answer.Type == DnsRecordType.TLSA && SameOwner(answer.Name, serviceOwner))
            .Select(answer => WithServiceOwner(answer, serviceOwner))
            .ToArray();
    }

    private static bool SameOwner(string? first, string second) =>
        string.Equals(first?.TrimEnd('.'), second.TrimEnd('.'), StringComparison.OrdinalIgnoreCase);

    private static DnsAnswer WithServiceOwner(DnsAnswer answer, string serviceOwner) {
        answer.Name = serviceOwner.TrimEnd('.');
        return answer;
    }
}
