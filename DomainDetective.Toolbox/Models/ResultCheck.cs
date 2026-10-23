namespace DomainDetective.Toolbox.Models;

/// <summary>How a row in a result checklist reads.</summary>
public enum ResultCheckState {
    /// <summary>A check that passed. Folded away under "N checks passed".</summary>
    Pass,
    /// <summary>A check that needs attention but is not broken.</summary>
    Warn,
    /// <summary>A check that failed.</summary>
    Fail,
    /// <summary>A fact about the record (TTL, length, provider) rather than a pass or fail.</summary>
    Fact
}

/// <summary>One row of a <c>ResultChecklist</c>.</summary>
public sealed record ResultCheck(string Label, string Value, ResultCheckState State) {
    /// <summary>A check that passes when <paramref name="isGood"/> is true and otherwise fails (or warns).</summary>
    /// <param name="label">What was checked.</param>
    /// <param name="isGood">True when the observed value is the healthy one.</param>
    /// <param name="value">The observed value, as shown to the reader.</param>
    /// <param name="warnOnly">Report a bad value as "review" instead of "fail".</param>
    public static ResultCheck Expect(string label, bool isGood, string value, bool warnOnly = false) =>
        new(label, value, isGood ? ResultCheckState.Pass : warnOnly ? ResultCheckState.Warn : ResultCheckState.Fail);

    /// <summary>A neutral fact about the record.</summary>
    public static ResultCheck Fact(string label, string value) => new(label, value, ResultCheckState.Fact);
}
