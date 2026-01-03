using System;
using System.Collections.Generic;
using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a desired state configuration object for use with DomainDetective.</summary>
/// <para>Supports loading an existing JSON configuration and/or building a configuration via a PowerShell DSL.</para>
/// <example>
///   <summary>Create an empty desired state configuration</summary>
///   <prefix>PS&gt; </prefix>
///   <code>$cfg = New-DDDesiredState</code>
///   <para>Creates an in-memory configuration object with defaults and no overrides.</para>
/// </example>
/// <example>
///   <summary>Load from JSON and override values</summary>
///   <prefix>PS&gt; </prefix>
///   <code>$cfg = New-DDDesiredState -LoadPath .\desired-state.json</code>
///   <para>Loads a configuration from disk, allowing further in-memory changes.</para>
/// </example>
/// <example>
///   <summary>Build using the DSL</summary>
///   <prefix>PS&gt; </prefix>
///   <code>$cfg = New-DDDesiredState { New-DDDesiredStateDmarc -Enabled $true -AllowedPolicies reject }</code>
///   <para>Builds a configuration by applying profile fragments returned from the script block.</para>
/// </example>
[Cmdlet(VerbsCommon.New, "DDDesiredState")]
[Alias("New-DesiredState")]
[OutputType(typeof(DesiredStateConfiguration))]
public sealed class CmdletNewDesiredState : PSCmdlet {
    /// <para>Optional path to load an existing desired state configuration JSON file.</para>
    [Parameter(Mandatory = false)]
    public string? LoadPath { get; set; }

    /// <para>Optional script block that returns desired state fragments (profiles/overrides) to be applied.</para>
    [Parameter(Mandatory = false, Position = 0)]
    public ScriptBlock? ScriptBlock { get; set; }

    /// <summary>Creates a configuration object, optionally loading JSON and applying DSL fragments.</summary>
    protected override void ProcessRecord() {
        DesiredStateConfiguration config;
        var loadPath = LoadPath;
        if (loadPath != null) {
            loadPath = loadPath.Trim();
        }
        if (!string.IsNullOrEmpty(loadPath)) {
            try {
                config = DesiredStateConfiguration.Load(loadPath);
            } catch (Exception ex) {
                ThrowTerminatingError(new ErrorRecord(ex, "DesiredStateLoadFailed", ErrorCategory.InvalidData, loadPath));
                return;
            }
        } else {
            config = new DesiredStateConfiguration();
        }

        config.Defaults ??= new DesiredStateProfile();
        config.Overrides ??= new List<DesiredStateOverride>();

        if (ScriptBlock != null) {
            var outputs = ScriptBlock.Invoke();
            ApplyDslOutputs(config, outputs);
        }

        config.Defaults.Normalize();
        WriteObject(config);
    }

    private void ApplyDslOutputs(DesiredStateConfiguration config, ICollection<PSObject> outputs) {
        if (outputs == null || outputs.Count == 0) return;

        foreach (var ps in outputs) {
            if (ps == null) continue;
            var o = ps.BaseObject;
            if (o == null) continue;

            if (o is DesiredStateProfile profile) {
                config.Defaults.Apply(profile);
                continue;
            }

            if (o is DesiredStateOverride ov) {
                config.Overrides.Add(ov);
                continue;
            }

            if (o is DesiredStateConfiguration cfg) {
                if (cfg.Defaults != null) {
                    config.Defaults.Apply(cfg.Defaults);
                }
                if (cfg.Overrides != null && cfg.Overrides.Count > 0) {
                    config.Overrides.AddRange(cfg.Overrides);
                }
                continue;
            }

            WriteError(new ErrorRecord(
                new InvalidOperationException($"Unsupported object type '{o.GetType().FullName}' returned from New-DDDesiredState script block."),
                "DesiredStateDslUnsupportedOutput",
                ErrorCategory.InvalidData,
                o));
        }
    }
}
