using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective.Reports;

/// <summary>JSON serialization of <see cref="DomainAssessmentReport"/> with readable enum names.</summary>
public static class DomainAssessmentJson {
    private static readonly JsonSerializerOptions Options = new() {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    private static readonly JsonSerializerOptions CompactOptions = new(Options) { WriteIndented = false };

    /// <summary>Serializes the assessment to indented JSON with camelCase names and enum names as strings.</summary>
    /// <param name="report">Assessment to serialize.</param>
    /// <returns>The JSON text.</returns>
    public static string Serialize(DomainAssessmentReport report) => Serialize(report, indented: true);

    /// <summary>Serializes the assessment with camelCase names and enum names as strings.</summary>
    /// <param name="report">Assessment to serialize.</param>
    /// <param name="indented">Indent for reading, or write compact JSON for storage.</param>
    /// <returns>The JSON text.</returns>
    public static string Serialize(DomainAssessmentReport report, bool indented) => JsonSerializer.Serialize(report, indented ? Options : CompactOptions);

    /// <summary>Reads an assessment written by <see cref="Serialize"/>.</summary>
    /// <param name="json">JSON text.</param>
    /// <returns>The assessment, or null for a JSON null.</returns>
    public static DomainAssessmentReport? Deserialize(string json) => JsonSerializer.Deserialize<DomainAssessmentReport>(json, Options);

    /// <summary>Serializes one check as compact JSON, for storing each check's result on its own.</summary>
    /// <param name="check">Check to serialize.</param>
    /// <returns>The JSON text.</returns>
    public static string SerializeCheck(CheckAssessment check) => JsonSerializer.Serialize(check, CompactOptions);

    /// <summary>Reads a check written by <see cref="SerializeCheck"/>.</summary>
    /// <param name="json">JSON text.</param>
    /// <returns>The check, or null for a JSON null.</returns>
    public static CheckAssessment? DeserializeCheck(string json) => JsonSerializer.Deserialize<CheckAssessment>(json, Options);
}
