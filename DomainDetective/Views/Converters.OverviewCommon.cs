namespace DomainDetective.Views;

/// <summary>Defines values for aggregate check state.</summary>
public enum AggregateCheckState {
    /// <summary>Provides aggregate check status info functionality.</summary>
    Unknown = 0,
    /// <summary>Provides aggregate check status info functionality.</summary>
    Pass = 1,
    /// <summary>Provides aggregate check status info functionality.</summary>
    Warning = 2,
    /// <summary>Provides aggregate check status info functionality.</summary>
    Fail = 3,
    /// <summary>Provides aggregate check status info functionality.</summary>
    Info = 4
}

/// <summary>Provides aggregate check status info functionality.</summary>
public sealed class AggregateCheckStatusInfo {
    /// <summary>Gets or sets the key value.</summary>
    public string Key { get; set; } = string.Empty;
    /// <summary>Gets or sets the label value.</summary>
    public string Label { get; set; } = string.Empty;
    /// <summary>Gets or sets the state value.</summary>
    public AggregateCheckState State { get; set; }
    /// <summary>Gets or sets the value value.</summary>
    public string Value { get; set; } = string.Empty;
    /// <summary>Gets or sets the detail value.</summary>
    public string Detail { get; set; } = string.Empty;
}
