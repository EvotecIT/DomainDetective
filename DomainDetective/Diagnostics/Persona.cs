using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

/// <summary>
/// Narration persona options for rendering assessments.
/// </summary>
public enum PersonaKind {
    Business,
    Funny,
    Geek,
    Noir,
    Pirate
}

/// <summary>
/// Provides simple persona-based narration for assessments in plain text.
/// </summary>
public static class AssessmentNarrator {
    public static string Narrate(Assessment a, PersonaKind persona) {
        var core = $"{a.Category}{(string.IsNullOrWhiteSpace(a.Target) ? string.Empty : $" ({a.Target})")} : {a.Message}";
        return persona switch {
            PersonaKind.Funny => core + " // not great, not terrible",
            PersonaKind.Geek  => core + " // see RFC?",
            PersonaKind.Noir  => core + " // it was a dark and stormy night…",
            PersonaKind.Pirate=> core.Replace(":", ": Arr!"),
            _ => core
        };
    }

    public static IEnumerable<string> Narrate(IEnumerable<Assessment> assessments, PersonaKind persona, int max = 12) {
        var prioritized = assessments
            .OrderByDescending(a => a.Severity)
            .ThenBy(a => a.Category)
            .ThenBy(a => a.Target ?? string.Empty)
            .Take(max);
        foreach (var a in prioritized)
            yield return Narrate(a, persona);
    }
}

