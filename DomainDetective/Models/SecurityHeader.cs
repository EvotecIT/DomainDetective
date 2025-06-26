namespace DomainDetective;

/// <summary>
/// Represents an HTTP security header.
/// </summary>
public sealed class SecurityHeader {
    /// <summary>Name of the header.</summary>
    public string Name { get; }

    /// <summary>Value of the header.</summary>
    public string Value { get; }

    /// <summary>Creates a new instance of <see cref="SecurityHeader"/>.</summary>
    public SecurityHeader(string name, string value) {
        Name = name;
        Value = value;
    }
}
