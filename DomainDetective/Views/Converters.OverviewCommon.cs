namespace DomainDetective.Views;

public enum AggregateCheckState {
    Unknown = 0,
    Pass = 1,
    Warning = 2,
    Fail = 3,
    Info = 4
}

public sealed class AggregateCheckStatusInfo {
    public string Key { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public AggregateCheckState State { get; set; }
    public string Value { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
}
