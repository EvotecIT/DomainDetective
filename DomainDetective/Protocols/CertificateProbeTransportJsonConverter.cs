using System;
using System.ComponentModel;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective;

/// <summary>Serializes protocol profile transport names without accepting numeric or unknown modes.</summary>
public sealed class CertificateProbeTransportJsonConverter : JsonConverter<CertificateProbeTransport> {
    /// <inheritdoc />
    public override CertificateProbeTransport Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) {
        if (reader.TokenType != JsonTokenType.String) throw new JsonException("A profile transport must be a named protocol mode.");
        return reader.GetString() switch {
            nameof(CertificateProbeTransport.DirectTls) => CertificateProbeTransport.DirectTls,
            nameof(CertificateProbeTransport.SmtpStartTls) => CertificateProbeTransport.SmtpStartTls,
            nameof(CertificateProbeTransport.FtpExplicitTls) => CertificateProbeTransport.FtpExplicitTls,
            nameof(CertificateProbeTransport.FtpImplicitTls) => CertificateProbeTransport.FtpImplicitTls,
            _ => throw new JsonException("Unknown profile transport.")
        };
    }
    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, CertificateProbeTransport value, JsonSerializerOptions options) {
        if (!Enum.IsDefined(typeof(CertificateProbeTransport), value)) throw new JsonException("Unknown profile transport.");
        writer.WriteStringValue(value.ToString());
    }
}

/// <summary>Uses the same exact transport names for configuration binding as for JSON profiles.</summary>
public sealed class CertificateProbeTransportConfigurationConverter : EnumConverter {
    /// <summary>Creates a protocol transport configuration converter.</summary>
    public CertificateProbeTransportConfigurationConverter() : base(typeof(CertificateProbeTransport)) { }
    /// <inheritdoc />
    public override object ConvertFrom(ITypeDescriptorContext? context, CultureInfo? culture, object value)
        => value is string token ? JsonSerializer.Deserialize<CertificateProbeTransport>(JsonSerializer.Serialize(token)) : base.ConvertFrom(context, culture, value)!;
}
