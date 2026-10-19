namespace DomainDetective.CLI.Wizard;

internal static partial class Ui {
    internal static string EvidenceStatus(DomainHealthCheck health, HealthCheckType check, string assessedStatus) =>
        OutputFormatters.HasCompletedCheck(health, check) ? assessedStatus
            : health.VerificationRequestedChecks.Contains(check) ? "[yellow]Incomplete[/]" : "[dim]Not assessed[/]";
}
