using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DomainDetective.Scanning;

namespace DomainDetective.CLI.Wizard;

/// <summary>Simple JSON/HTML exporters for DomainScanResult.</summary>
public static class Exporters
{
    public static class JsonExporter
    {
        private static readonly JsonSerializerOptions _opts = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
        public static string Serialize(DomainScanResult res) => JsonSerializer.Serialize(res, _opts);
    }

    public static class HtmlExporter
    {
        public static string Render(DomainScanResult res)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!doctype html><html><head><meta charset='utf-8'><title>DomainDetective Report</title>");
            sb.AppendLine("<style>body{font-family:ui-sans-serif,system-ui;background:#0b0f10;color:#e5f2e5} .ok{color:#6ee7a8}.bad{color:#f87171}.warn{color:#fbbf24} .card{border:1px solid #1f2937;padding:12px;border-radius:8px;margin:10px;background:#111827}</style>");
            sb.AppendLine("</head><body>");
            sb.AppendLine($"<h1>DomainDetective — {Escape(res.Domain)}</h1>");
            foreach (var note in res.Notes) { sb.AppendLine($"<p class='warn' role='status'>{Escape(note)}</p>"); }
            sb.AppendLine("<div class='card'><h2>DNS</h2>");
            sb.Append("<ul>");
            foreach (var ns in res.Dns.Ns) sb.Append($"<li>NS: {Escape(ns)}</li>");
            foreach (var mx in res.Dns.Mx.OrderBy(m => m.Preference)) sb.Append($"<li>MX: {mx.Preference} {Escape(mx.Host)}</li>");
            sb.Append($"<li>DNSSEC: {Flag(res.Dns.DnssecEnabled)}</li>");
            sb.Append($"<li>AXFR: {Flag(res.Dns.ZoneTransferOpen, "❌ open", "✅ closed")}</li>");
            sb.Append("</ul></div>");

            sb.AppendLine("<div class='card'><h2>Email</h2><ul>");
            sb.Append($"<li>SPF: {Escape(res.Mail.SpfRecord ?? "")} </li>");
            sb.Append($"<li>DMARC: {Escape(res.Mail.DmarcRecord ?? "")} </li>");
            sb.Append($"<li>BIMI: {Escape(res.Mail.BimiRecord ?? "")} </li>");
            sb.Append($"<li>MTA-STS: {Escape(res.Mail.MtaStsPolicy ?? "")} </li>");
            sb.Append($"<li>TLS-RPT: {Escape(res.Mail.TlsRpt ?? "")} </li>");
            sb.Append("</ul></div>");

            sb.AppendLine("<div class='card'><h2>Web</h2><ul>");
            sb.Append($"<li>HTTP: {Flag(res.Web.HttpOk)} / HTTPS: {Flag(res.Web.HttpsOk)}</li>");
            sb.Append($"<li>H2: {Flag(res.Web.Http2)} / H3: {Flag(res.Web.Http3)}</li>");
            sb.Append($"<li>HSTS: {Flag(res.Web.Hsts)}</li>");
            if (res.Web.Tls is not null)
                sb.Append($"<li>TLS: {Escape(res.Web.Tls.Subject ?? "")} / {Escape(res.Web.Tls.Issuer ?? "")} / NotAfter {res.Web.Tls.NotAfter:u}</li>");
            sb.Append("</ul></div>");

            sb.AppendLine("<div class='card'><h2>Reputation</h2><ul>");
            sb.Append($"<li>Registrar: {Escape(res.Reputation.WhoisRegistrar ?? "")}</li>");
            sb.Append($"<li>RDAP: {Escape(res.Reputation.RdapHandle ?? "")}</li>");
            sb.Append($"<li>RPKI: {Flag(res.Reputation.RpkiValid)}</li>");
            if (res.Reputation.Blacklists.Count > 0)
                sb.Append($"<li>Blacklists: {Escape(string.Join(", ", res.Reputation.Blacklists))}</li>");
            sb.Append("</ul></div>");

            sb.AppendLine("</body></html>");
            return sb.ToString();
        }

        private static string Flag(bool? value, string positive = "✅", string negative = "❌") =>
            value.HasValue ? value.Value ? positive : negative : "Not assessed";

        private static string Escape(string s) => System.Net.WebUtility.HtmlEncode(s);
    }
}

