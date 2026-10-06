using System;
using System.Linq;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using System.IO;
using System.Net.Mail;

namespace DomainDetective;

public partial class AutodiscoverHttpAnalysis {
    private static (bool Valid, string? Namespace, bool NamespaceValid, bool Recognized, string? Kind) ParseXml(string content) {
        try {
            using var reader = XmlReader.Create(new StringReader(content), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            var doc = XDocument.Load(reader);
            var root = doc.Root;
            string? ns = root?.Name.NamespaceName;
            if (root?.Name.LocalName != "Autodiscover") return (false, ns, false, false, null);
            bool acceptedRoot = IsSchema(ns, "responseschema/2006");
            var response = root.Elements().FirstOrDefault(element => element.Name.LocalName == "Response" &&
                (IsSchema(element.Name.NamespaceName, "responseschema/2006") || IsSchema(element.Name.NamespaceName, "outlook/responseschema/2006a")));
            if (!acceptedRoot || response == null) return (true, ns, acceptedRoot, false, null);
            XNamespace responseNs = response.Name.Namespace;
            var error = response.Element(responseNs + "Error");
            if (error?.Element(responseNs + "ErrorCode") is XElement code && int.TryParse(code.Value, out _))
                return (true, ns, true, true, "error");
            var account = response.Element(responseNs + "Account");
            string? action = account?.Element(responseNs + "Action")?.Value.Trim();
            bool emailAccount = account?.Element(responseNs + "AccountType")?.Value.Trim() == "email";
            bool known = emailAccount && (action == "settings" && account!.Elements(responseNs + "Protocol")
                    .Any(protocol => !string.IsNullOrWhiteSpace(protocol.Element(responseNs + "Type")?.Value))
                || action == "redirectAddr" && IsEmailAddress(account?.Element(responseNs + "RedirectAddr")?.Value)
                || action == "redirectUrl" && TryHttpUrl(account?.Element(responseNs + "RedirectUrl")?.Value, out _));
            return (true, ns, true, known, known ? action : null);
        } catch (XmlException) { return (false, null, false, false, null); }
    }

    private static bool IsSchema(string? value, string suffix) => value == "http://schemas.microsoft.com/exchange/autodiscover/" + suffix
        || value == "https://schemas.microsoft.com/exchange/autodiscover/" + suffix;

    private static bool IsEmailAddress(string? value) {
        if (string.IsNullOrWhiteSpace(value)) return false;
        try {
            var address = new MailAddress(value);
            return address.Address.Equals(value!.Trim(), StringComparison.OrdinalIgnoreCase);
        } catch (FormatException) { return false; }
    }

    private static bool TryHttpUrl(string? value, out Uri? uri) {
        if (Uri.TryCreate(value, UriKind.Absolute, out uri) && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
            && string.IsNullOrEmpty(uri.UserInfo)) return true;
        uri = null; return false;
    }

    private static string? ParseJsonEndpoint(string body) {
        try {
            JsonDocument document;
            try {
                document = JsonDocument.Parse(body);
            } catch (JsonException) when (body.Contains("\\\"")) {
                // Preserve the supported legacy response with escaped object delimiters.
                // Strict JSON always wins; normalized URLs still require normal validation
                // and the caller performs HTTP/XML confirmation before reporting discovery.
                document = JsonDocument.Parse(body.Replace("\\\"", "\"").Replace("\\\\", "\\"));
            }
            using var parsed = document;
            var root = parsed.RootElement;
            if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("Url", out var property)
                && property.ValueKind == JsonValueKind.String && TryHttpUrl(property.GetString(), out var uri)) return uri!.AbsoluteUri;
            if (root.ValueKind == JsonValueKind.Array) {
                foreach (var item in root.EnumerateArray()) {
                    if (item.ValueKind == JsonValueKind.Object && item.TryGetProperty("Url", out var value)
                        && value.ValueKind == JsonValueKind.String && TryHttpUrl(value.GetString(), out var arrayUri)) return arrayUri!.AbsoluteUri;
                }
            }
        } catch (JsonException) { }
        return null;
    }

    private static string BuildAutodiscoverRequestXml(string email) {
        XNamespace ns = "http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006";
        return new XDocument(new XElement(ns + "Autodiscover", new XElement(ns + "Request", new XElement(ns + "EMailAddress", email),
            new XElement(ns + "AcceptableResponseSchema", "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a")))).ToString(SaveOptions.DisableFormatting);
    }
}
