using System;
using System.Collections.Generic;
using System.Linq;
using Spectre.Console;

namespace DomainDetective.CLI.Wizard;

internal static class PersonaFormatter {
    private sealed record PersonaColors(string Tag, string Data, string Flair, string Ok, string Warn, string Err)
    {
        public static PersonaColors For(PersonaKind persona) => persona switch
        {
            PersonaKind.Funny  => new("springgreen1", "white", "yellow3", "green3", "yellow1", "red1"),
            PersonaKind.Geek   => new("orchid1",     "white", "slateblue1", "chartreuse1", "gold1", "deeppink1"),
            PersonaKind.Noir   => new("grey78",       "white", "grey62",    "aquamarine1", "lightgoldenrod1", "indianred1"),
            PersonaKind.Pirate => new("gold1",        "white", "yellow3",   "green1", "yellow1", "red1"),
            _                  => new("steelblue1",   "white", "grey70",   "green3", "khaki1", "red3")
        };
    }

    public static string StepColor(PersonaKind persona) => persona switch
    {
        PersonaKind.Funny  => "springgreen1",
        PersonaKind.Geek   => "orchid1",
        PersonaKind.Noir   => "grey78",
        PersonaKind.Pirate => "gold1",
        _                  => "deepskyblue1" // business
    };

    public static string Format(Assessment a, PersonaKind persona) {
        var colors = PersonaColors.For(persona);
        var icon = a.Severity switch {
            AssessmentSeverity.Error => $"[{colors.Err}]❌[/]",
            AssessmentSeverity.Warning => $"[{colors.Warn}]⚠️[/]",
            _ => "[blue]ℹ️[/]"
        };
        var (title, phrase) = AssessmentNarrator.NarrateParts(a, persona);
        var cat = $"[bold {colors.Tag}]{a.Category.EscapeMarkup()}[/]";
        var tgt = string.IsNullOrWhiteSpace(a.Target) ? string.Empty : $" [dim]({a.Target.EscapeMarkup()})[/]";
        var data = $"[{colors.Data}]{title.EscapeMarkup()}[/]";
        var flair = string.IsNullOrWhiteSpace(phrase) ? string.Empty : $" [grey]|[/] [italic {colors.Flair}]{phrase.EscapeMarkup()}[/]";
        return $"{icon} {cat}{tgt}: {data}{flair}";
    }

    public static IEnumerable<string> FormatSummary(IEnumerable<Assessment> assessments, PersonaKind persona, int max = 12) {
        foreach (var a in assessments
            .OrderByDescending(a => a.Severity)
            .ThenBy(a => a.Category)
            .ThenBy(a => a.Target ?? string.Empty)
            .Take(max))
        {
            yield return Format(a, persona);
        }
    }
}
