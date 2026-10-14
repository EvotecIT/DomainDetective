using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective.Helpers;

/// <summary>Writes failure diagnostics without unsupported reflection objects or arbitrary exception data.</summary>
internal sealed class ExceptionJsonConverter : JsonConverter<Exception> {
    public override bool CanConvert(Type typeToConvert) => typeof(Exception).IsAssignableFrom(typeToConvert);

    public override Exception Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) {
        throw new NotSupportedException("Failure diagnostics in scan JSON cannot be deserialized as an Exception.");
    }

    public override void Write(Utf8JsonWriter writer, Exception value, JsonSerializerOptions options) {
        writer.WriteStartObject();
        writer.WriteString("Type", value.GetType().FullName);
        writer.WriteString("Message", value.Message);
        writer.WriteNumber("HResult", value.HResult);
        writer.WriteString("StackTrace", value.StackTrace);
        writer.WritePropertyName("InnerException");
        JsonSerializer.Serialize(writer, value.InnerException, options);
        if (value is AggregateException aggregate) {
            writer.WritePropertyName("InnerExceptions");
            JsonSerializer.Serialize(writer, aggregate.InnerExceptions, options);
        }
        writer.WriteEndObject();
    }
}
