using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

/// <summary>
/// Narration persona options for rendering assessments.
/// </summary>
public enum PersonaKind {
    /// <summary>Provides assessment narrator functionality.</summary>
    Business,
    /// <summary>Provides assessment narrator functionality.</summary>
    Funny,
    /// <summary>Provides assessment narrator functionality.</summary>
    Geek,
    /// <summary>Provides assessment narrator functionality.</summary>
    Noir,
    /// <summary>Provides assessment narrator functionality.</summary>
    Pirate
}

/// <summary>
/// Provides persona-based narration for assessments with deterministic phrase selection.
/// </summary>
public static class AssessmentNarrator {
    /// <summary>
    /// Returns a concise narrative string for an assessment using persona lexicon.
    /// Uses recommendation title (or message) and appends a persona phrase deterministically.
    /// </summary>
    public static string Narrate(Assessment a, PersonaKind persona) {
        var advice = RecommendationCatalog.For(a);
        var title = string.IsNullOrWhiteSpace(advice?.Title) ? a.Message : advice!.Title;
        var key = string.Concat(a.Code ?? a.Category ?? string.Empty, "|", a.Target ?? string.Empty);
        var phrase = PersonaLexicon.Pick(persona, a.Severity, key);
        return string.IsNullOrWhiteSpace(phrase) ? title : $"{title} — {phrase}";
    }

    /// <summary>Executes the narrate operation.</summary>
    public static IEnumerable<string> Narrate(IEnumerable<Assessment> assessments, PersonaKind persona, int max = 12) {
        var prioritized = assessments
            .OrderByDescending(a => a.Severity)
            .ThenBy(a => a.Category)
            .ThenBy(a => a.Target ?? string.Empty)
            .Take(max);
        foreach (var a in prioritized)
            yield return Narrate(a, persona);
    }

    /// <summary>
    /// Persona-styled narration with advisory context (title + why) and deterministic phrase.
    /// </summary>
    public static string NarrateDetailed(Assessment a, PersonaKind persona) {
        var advice = RecommendationCatalog.For(a);
        var core = $"{advice.Title} — {advice.Why}";
        var key = string.Concat(a.Code ?? a.Category ?? string.Empty, "|", a.Target ?? string.Empty);
        var phrase = PersonaLexicon.Pick(persona, a.Severity, key);
        return string.IsNullOrWhiteSpace(phrase) ? core : $"{core} — {phrase}";
    }

    /// <summary>
    /// Returns the core title (data) and persona phrase separately for advanced formatting.
    /// </summary>
    public static (string Title, string Phrase) NarrateParts(Assessment a, PersonaKind persona)
    {
        var advice = RecommendationCatalog.For(a);
        var title = string.IsNullOrWhiteSpace(advice?.Title) ? a.Message : advice!.Title;
        var key = string.Concat(a.Code ?? a.Category ?? string.Empty, "|", a.Target ?? string.Empty);
        var phrase = PersonaLexicon.Pick(persona, a.Severity, key) ?? string.Empty;
        return (title, phrase);
    }
}

/// <summary>
/// Persona lexicon and deterministic phrase picker (severity → phrase arrays per persona).
/// </summary>
public static class PersonaLexicon {
    private static readonly string[] BizOk   = new[] { "Confirmed", "All good", "Compliant", "Healthy", "Meets policy" };
    private static readonly string[] BizWarn = new[] { "Needs attention", "Advisory", "Degraded", "Weak posture", "Consider changes" };
    private static readonly string[] BizErr  = new[] { "Non-compliant", "Failed", "Broken", "Critical", "Blocking" };

    private static readonly string[] FunOk   = new[] { "Niiiice", "Chef’s kiss", "Rock solid", "Green as grass", "Ship it" };
    private static readonly string[] FunWarn = new[] { "Little sus", "Hmmmm", "I’ve seen better", "Keep an eye", "Could be spicier" };
    private static readonly string[] FunErr  = new[] { "Oof", "Yikes", "Nope nope nope", "On fire", "Hard fail" };

    private static readonly string[] GeekOk   = new[] { "LGTM", "Spec-compliant", "Deterministic", "Idempotent", "Consistent" };
    private static readonly string[] GeekWarn = new[] { "Non-ideal", "Edge-case", "Heuristic match", "Low entropy", "Suboptimal" };
    private static readonly string[] GeekErr  = new[] { "Invariant violated", "Assertion failed", "Null ref IRL", "Out-of-spec", "Catastrophic" };

    private static readonly string[] NoirOk   = new[] { "Clean as a whistle", "Checks out", "Nothing suspicious", "Buttoned up", "Solid alibi" };
    private static readonly string[] NoirWarn = new[] { "Smells funny", "Watch this angle", "Loose thread", "Shaky alibi", "Keep digging" };
    private static readonly string[] NoirErr  = new[] { "Caught red-handed", "Dead end", "Leaking bad", "Open secret", "Crime scene" };

    private static readonly string[] PirOk   = new[] { "Fair winds", "Aye, solid", "Shipshape", "Treasure found", "Ports secured" };
    private static readonly string[] PirWarn = new[] { "Reef ahead", "Storm brewin’", "Trim the sails", "Keep a weather eye", "Careful, ye lubber" };
    private static readonly string[] PirErr  = new[] { "Scuttled", "Keelhauled", "Breach below", "Mutiny!", "Dead in the water" };

    // Step verbs per persona (used for progress narration)
    private static readonly string[] BizStep = new[] { "Checking", "Verifying", "Evaluating", "Assessing", "Analyzing" };
    private static readonly string[] FunStep = new[] { "Peeking at", "Poking", "Sniffing", "Tickling", "Investigating" };
    private static readonly string[] GeekStep = new[] { "Resolving", "Parsing", "Diffing", "Enumerating", "Fingerprinting" };
    private static readonly string[] NoirStep = new[] { "Shadowing", "Trailing", "Interrogating", "Dusting for prints on", "Tailoring the lead on" };
    private static readonly string[] PirStep = new[] { "Chartin’", "Spyglassin’", "Soundin’", "Boardin’", "Pillagin’" };

    /// <summary>Executes the pick operation.</summary>
    public static string? Pick(PersonaKind persona, AssessmentSeverity severity, string key) {
        var (ok, warn, err) = persona switch {
            PersonaKind.Funny  => (FunOk,  FunWarn,  FunErr),
            PersonaKind.Geek   => (GeekOk, GeekWarn, GeekErr),
            PersonaKind.Noir   => (NoirOk, NoirWarn, NoirErr),
            PersonaKind.Pirate => (PirOk,  PirWarn,  PirErr),
            _                  => (BizOk,  BizWarn,  BizErr)
        };
        var pool = severity switch {
            AssessmentSeverity.Error   => err,
            AssessmentSeverity.Warning => warn,
            _                          => ok
        };
        if (pool == null || pool.Length == 0) return null;
        var idx = StableIndex(key ?? string.Empty, pool.Length);
        return pool[idx];
    }

    private static int StableIndex(string key, int modulo) {
        if (modulo <= 0) return 0;
        unchecked {
            // FNV-1a 32-bit over UTF-16 chars (stable across processes)
            const uint fnvOffset = 2166136261;
            const uint fnvPrime  = 16777619;
            uint hash = fnvOffset;
            foreach (var ch in key) {
                hash ^= ch;
                hash *= fnvPrime;
            }
            var idx = (int)(hash % (uint)modulo);
            if (idx < 0) idx = -idx;
            return idx;
        }
    }

    /// <summary>Executes the step verb operation.</summary>
    public static string StepVerb(PersonaKind persona, string opKey) {
        var pool = persona switch {
            PersonaKind.Funny  => FunStep,
            PersonaKind.Geek   => GeekStep,
            PersonaKind.Noir   => NoirStep,
            PersonaKind.Pirate => PirStep,
            _                  => BizStep
        };
        if (pool == null || pool.Length == 0) return "Checking";
        var idx = StableIndex(opKey ?? string.Empty, pool.Length);
        return pool[idx];
    }
}
