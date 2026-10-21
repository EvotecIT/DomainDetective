using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective;

/// <summary>Serializes protocol profile transport names without accepting numeric or unknown modes.</summary>
public sealed class CertificateProbeTransportJsonConverter : JsonConverter<CertificateProbeTransport> {
    /// <inheritdoc />
    public override CertificateProbeTransport Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) {
        if (reader.TokenType != JsonTokenType.String) throw new JsonException("A profile transport must be a named protocol mode.");
        string value = reader.GetString() ?? string.Empty;
        if (value.Length == 0 || !char.IsLetter(value[0]) || !Enum.TryParse(value, false, out CertificateProbeTransport mode) || !Enum.IsDefined(typeof(CertificateProbeTransport), mode)) throw new JsonException("Unknown profile transport.");
        return mode;
    }
    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, CertificateProbeTransport value, JsonSerializerOptions options) {
        if (!Enum.IsDefined(typeof(CertificateProbeTransport), value)) throw new JsonException("Unknown profile transport.");
        writer.WriteStringValue(value.ToString());
    }
}
