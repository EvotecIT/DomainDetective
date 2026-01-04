using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace DomainDetective.CLI.Commands;

internal sealed class RunsOpenCommand : AsyncCommand<RunsOpenCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [Description("Artifacts root directory (defaults to ./artifacts)")]
        [CommandOption("--artifacts-dir <PATH>")]
        public string? ArtifactsDir { get; set; }

        [Description("Subject (domain/URL) to open last run for")]
        [CommandOption("--subject <SUBJECT>")]
        public string? Subject { get; set; }

        [Description("Run directory to open (overrides subject lookup)")]
        [CommandOption("--dir <PATH>")]
        public string? RunDirectory { get; set; }
    }

    private sealed class IndexRecord
    {
        public ArtifactMeta? meta { get; set; }
        public string? dir { get; set; }
    }
    private sealed class ArtifactMeta
    {
        public string? Subject { get; set; }
        public DateTimeOffset GeneratedAt { get; set; }
    }

    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Deserialize")] 
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Deserialize")] 
    public override Task<int> ExecuteAsync(CommandContext context, Settings settings)
    {
        string? targetDir = settings.RunDirectory;
        if (string.IsNullOrWhiteSpace(targetDir))
        {
            var root = !string.IsNullOrWhiteSpace(settings.ArtifactsDir)
                ? settings.ArtifactsDir!
                : Path.Combine(Directory.GetCurrentDirectory(), "artifacts");
            if (!Directory.Exists(root))
            {
                AnsiConsole.MarkupLine($"[yellow]No artifacts directory found:[/] {root}");
                return Task.FromResult(1);
            }

            if (!string.IsNullOrWhiteSpace(settings.Subject))
            {
                var safe = DomainDetective.Reports.FilePathHelper.MakeFileSafe(settings.Subject!);
                var idx = Path.Combine(root, safe, "index.jsonl");
                var last = ReadIndex(idx).OrderByDescending(r => r.meta!.GeneratedAt).FirstOrDefault();
                targetDir = last?.dir;
            }
            else
            {
                // Pick most recent across all subjects
                var latest = Directory.EnumerateDirectories(root)
                    .SelectMany(d => ReadIndex(Path.Combine(d, "index.jsonl")))
                    .OrderByDescending(r => r.meta!.GeneratedAt)
                    .FirstOrDefault();
                targetDir = latest?.dir;
            }
        }

        if (string.IsNullOrWhiteSpace(targetDir) || !Directory.Exists(targetDir))
        {
            AnsiConsole.MarkupLine("[red]No run directory found to open.[/]");
            return Task.FromResult(1);
        }

        // Prefer opening scan.json if present; otherwise the directory
        string toOpen = Path.Combine(targetDir, "scan.json");
        if (!File.Exists(toOpen)) toOpen = targetDir;

        try
        {
            OpenWithShell(toOpen);
            AnsiConsole.MarkupLine($"[green]Opened:[/] {toOpen}");
            return Task.FromResult(0);
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Failed to open:[/] {ex.Message}");
            return Task.FromResult(1);
        }
    }

    private static System.Collections.Generic.IEnumerable<IndexRecord> ReadIndex(string path)
    {
        if (!File.Exists(path)) yield break;
        using var stream = File.OpenRead(path);
        using var reader = new StreamReader(stream);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            IndexRecord? rec = null;
            try { rec = JsonSerializer.Deserialize<IndexRecord>(line, DomainDetective.Helpers.JsonOptions.Default); } catch { }
            if (rec?.meta != null && !string.IsNullOrWhiteSpace(rec.dir)) yield return rec;
        }
    }

    private static void OpenWithShell(string path)
    {
        var p = new System.Diagnostics.Process();
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = path,
            UseShellExecute = true
        };
        p.StartInfo = psi;
        p.Start();
    }
}
