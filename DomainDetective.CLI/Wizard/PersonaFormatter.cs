using System;
using System.Collections.Generic;
using System.Linq;
using Spectre.Console;

namespace DomainDetective.CLI.Wizard;

internal static class PersonaFormatter {
    public static string Format(Assessment a, PersonaKind persona) {
        var icon = a.Severity switch {
            AssessmentSeverity.Error => "[red]❌[/]",
            AssessmentSeverity.Warning => "[yellow]⚠️[/]",
            _ => "[blue]ℹ️[/]"
        };
        var narrated = AssessmentNarrator.Narrate(a, persona).EscapeMarkup();
        return $"{icon} [bold]{a.Category.EscapeMarkup()}[/]{(string.IsNullOrWhiteSpace(a.Target) ? string.Empty : $" [dim]({a.Target.EscapeMarkup()})[/]")}: {narrated}";
    }

    public static IEnumerable<string> FormatSummary(IEnumerable<Assessment> assessments, PersonaKind persona, int max = 12) {
        foreach (var a in assessments
            .OrderByDescending(a => a.Severity)
            .ThenBy(a => a.Category)
            .ThenBy(a => a.Target ?? string.Empty)
            .Take(max))
            yield return Format(a, persona);
    }
}
