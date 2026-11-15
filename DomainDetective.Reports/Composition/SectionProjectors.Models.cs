using System.Collections.Generic;

namespace DomainDetective.Reports;

public static partial class SectionProjectors {
    public sealed class SimpleFinding
    {
        public string Severity { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public SimpleFinding() {}
        public SimpleFinding(string severity, string code, string target, string message) { Severity = severity; Code = code; Target = target; Message = message; }
    }

    public sealed class Microsoft365Section
    {
        public sealed class ServiceRow
        {
            public string Service { get; set; } = string.Empty;
            public string Status { get; set; } = "-";
            public string Confidence { get; set; } = "-";
            public string Evidence { get; set; } = string.Empty;
        }

        public sealed class DomainRow
        {
            public string Domain { get; set; } = string.Empty;
            public string Role { get; set; } = string.Empty;
            public string Confidence { get; set; } = "-";
            public string Evidence { get; set; } = string.Empty;
        }

        public sealed class SubdomainRow
        {
            public string Name { get; set; } = string.Empty;
            public string Role { get; set; } = string.Empty;
            public string Resolution { get; set; } = string.Empty;
        }

        public sealed class ApplicationRow
        {
            public string Name { get; set; } = string.Empty;
            public string Category { get; set; } = string.Empty;
            public string EvidenceKind { get; set; } = string.Empty;
            public string Confidence { get; set; } = "-";
            public string Evidence { get; set; } = string.Empty;
        }

        public sealed class EvidenceRow
        {
            public string Label { get; set; } = string.Empty;
            public string Category { get; set; } = string.Empty;
            public string Confidence { get; set; } = "-";
            public string Evidence { get; set; } = string.Empty;
        }

        public string Status { get; set; } = "-";
        public bool IsMicrosoft365Tenant { get; set; }
        public string DetectionConfidence { get; set; } = "-";
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
        public List<string> Highlights { get; } = new();
        public List<ServiceRow> Services { get; } = new();
        public List<DomainRow> Domains { get; } = new();
        public List<SubdomainRow> Subdomains { get; } = new();
        public List<ApplicationRow> Applications { get; } = new();
        public List<EvidenceRow> Evidence { get; } = new();
    }

}
