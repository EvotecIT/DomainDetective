using DomainDetective;

namespace DomainDetective.PowerShell;

internal static class PersonaState {
    private static readonly object _lock = new();

    public static bool Enabled { get; private set; }
    public static PersonaKind Persona { get; private set; } = PersonaKind.Business;
    public static bool Live { get; private set; }
    public static bool NarrateVerbose { get; private set; }

    public static void Set(PersonaKind persona, bool live, bool narrateVerbose) {
        lock (_lock) {
            Enabled = true;
            Persona = persona;
            Live = live;
            NarrateVerbose = narrateVerbose;
        }
    }

    public static void Disable() {
        lock (_lock) {
            Enabled = false;
            Persona = PersonaKind.Business;
            Live = false;
            NarrateVerbose = false;
        }
    }

    public static (bool enabled, PersonaKind persona, bool live, bool narrateVerbose) Get()
    {
        lock (_lock) {
            return (Enabled, Persona, Live, NarrateVerbose);
        }
    }
}

