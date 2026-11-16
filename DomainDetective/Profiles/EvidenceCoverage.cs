namespace DomainDetective.Profiles;

/// <summary>
/// The one rule every evidence source follows when it turns its answers into an <see cref="EvidenceState"/>. A source
/// is complete only when every query it asked answered and nothing was capped; a positive finding (a listing, a
/// threat hit) is reported, but it never makes partial coverage complete.
/// </summary>
public static class EvidenceCoverage {
    /// <summary>Derives a state from how many queries were asked and answered.</summary>
    /// <param name="asked">Queries the source asked (lists, feeds, addresses, record types).</param>
    /// <param name="answered">Queries that answered.</param>
    /// <param name="found">True when an answer reported something (a listing, a value).</param>
    /// <param name="capped">True when the source stopped early (row, page or address limit).</param>
    /// <returns>
    /// <see cref="EvidenceState.NotQueried"/> when nothing was asked, <see cref="EvidenceState.Failed"/> when nothing
    /// answered, <see cref="EvidenceState.Partial"/> when some answers are missing or the source was capped,
    /// otherwise <see cref="EvidenceState.Observed"/> when something was found and <see cref="EvidenceState.Clean"/>
    /// when the answers were negative.
    /// </returns>
    public static EvidenceState From(int asked, int answered, bool found, bool capped = false) {
        if (asked <= 0) return EvidenceState.NotQueried;
        if (answered <= 0) return EvidenceState.Failed;
        if (answered < asked || capped) return EvidenceState.Partial;
        return found ? EvidenceState.Observed : EvidenceState.Clean;
    }

    /// <summary>Lowers a complete state to <see cref="EvidenceState.Partial"/> when part of the source is missing.</summary>
    /// <param name="state">State the source reported.</param>
    /// <param name="partial">True when the source was capped or partly failed.</param>
    public static EvidenceState Limit(EvidenceState state, bool partial) =>
        partial && state is EvidenceState.Observed or EvidenceState.Clean ? EvidenceState.Partial : state;
}
