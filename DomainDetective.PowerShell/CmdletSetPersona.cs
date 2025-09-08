using System.Management.Automation;
using DomainDetective;

namespace DomainDetective.PowerShell {

    /// <summary>Enables, configures, or disables narration personas.</summary>
    [Cmdlet(VerbsCommon.Set, "DDPersona", DefaultParameterSetName = "View")]
    [Alias("Set-DDNarrator")]
    public sealed class CmdletSetPersona : PSCmdlet {
        private const string SetParams = "Set";
        private const string OffParams = "Off";
        private const string ViewParams = "View";

        /// <summary>Persona style to use.</summary>
        [Parameter(Mandatory = true, ParameterSetName = SetParams)]
        public PersonaKind Persona { get; set; } = PersonaKind.Business;

        /// <summary>Enable live narration.</summary>
        [Parameter(Mandatory = false, ParameterSetName = SetParams)]
        public SwitchParameter Live { get; set; }

        /// <summary>Include verbose narration.</summary>
        [Parameter(Mandatory = false, ParameterSetName = SetParams)]
        public SwitchParameter NarrateVerbose { get; set; }

        /// <summary>Disable persona narration.</summary>
        [Parameter(Mandatory = true, ParameterSetName = OffParams)]
        public SwitchParameter Off { get; set; }

        /// <summary>Executes the persona configuration.</summary>
        protected override void ProcessRecord() {
            switch (ParameterSetName) {
                case SetParams:
                    PersonaState.Set(Persona, Live.IsPresent, NarrateVerbose.IsPresent);
                    WriteObject(new {
                        Enabled = true,
                        Persona,
                        Live = (bool)Live,
                        NarrateVerbose = (bool)NarrateVerbose
                    });
                    break;
                case OffParams:
                    PersonaState.Disable();
                    WriteObject(new {
                        Enabled = false,
                        Persona = PersonaKind.Business,
                        Live = false,
                        NarrateVerbose = false
                    });
                    break;
                default:
                    var (enabled, persona, live, narrVerbose) = PersonaState.Get();
                    WriteObject(new {
                        Enabled = enabled,
                        Persona = persona,
                        Live = live,
                        NarrateVerbose = narrVerbose
                    });
                    break;
            }
        }
    }
}
