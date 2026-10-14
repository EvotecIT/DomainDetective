using System;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective.Helpers;

/// <summary>Writes public certificate metadata without native handles or private key objects.</summary>
/// <remarks>The projection is for reporting, not certificate reconstruction. Disposed certificates are written as null.</remarks>
internal sealed class X509CertificateJsonConverter : JsonConverter<X509Certificate2> {
    public override X509Certificate2 Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) {
        throw new NotSupportedException("Certificate metadata in scan JSON cannot be deserialized as an X509Certificate2.");
    }

    public override void Write(Utf8JsonWriter writer, X509Certificate2 value, JsonSerializerOptions options) {
        if (value.Handle == IntPtr.Zero) {
            writer.WriteNullValue();
            return;
        }
        writer.WriteStartObject();
        writer.WriteString("Subject", value.Subject);
        writer.WriteString("Issuer", value.Issuer);
        writer.WriteString("Thumbprint", value.Thumbprint);
        writer.WriteString("SerialNumber", value.SerialNumber);
        writer.WriteString("NotBefore", value.NotBefore.ToUniversalTime());
        writer.WriteString("NotAfter", value.NotAfter.ToUniversalTime());
        writer.WriteEndObject();
    }
}
