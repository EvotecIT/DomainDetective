using System;
using System.ComponentModel;
using System.Globalization;
using System.Text.Json;

namespace DomainDetective.Providers.Endpoint;

/// <summary>Uses the same matcher tokens for .NET configuration binding as for JSON data files.</summary>
public sealed class EndpointMatcherConfigurationConverter : EnumConverter {
    /// <summary>Creates a portable matcher token converter.</summary>
    public EndpointMatcherConfigurationConverter() : base(typeof(EndpointMatcherType)) { }
    /// <inheritdoc />
    public override object ConvertFrom(ITypeDescriptorContext? context, CultureInfo? culture, object value)
        => value is string token ? JsonSerializer.Deserialize<EndpointMatcherType>(JsonSerializer.Serialize(token)) : base.ConvertFrom(context, culture, value)!;
}

/// <summary>Uses the same effect tokens for .NET configuration binding as for JSON data files.</summary>
public sealed class EndpointEffectConfigurationConverter : EnumConverter {
    /// <summary>Creates a portable effect token converter.</summary>
    public EndpointEffectConfigurationConverter() : base(typeof(EndpointRuleEffect)) { }
    /// <inheritdoc />
    public override object ConvertFrom(ITypeDescriptorContext? context, CultureInfo? culture, object value)
        => value is string token ? JsonSerializer.Deserialize<EndpointRuleEffect>(JsonSerializer.Serialize(token)) : base.ConvertFrom(context, culture, value)!;
}
