using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace DomainDetective.CLI.Commands;

internal sealed class RunsListCommand : AsyncCommand<RunsListCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [Description("Artifacts root directory (defaults to ./artifacts)")]
        [CommandOption("--artifacts-dir <PATH>")]
        public string? ArtifactsDir { get; set; }

        [Description("Subject filter (domain/URL)")]
        [CommandOption("--subject <SUBJECT>")]
        public string? Subject { get; set; }

        [Description("Maximum runs to list")]
        [CommandOption("-n|--count <N>")]
        [DefaultValue(10)]
        public int Count { get; set; } = 10;

        [Description("Output JSON instead of a table")]
        [CommandOption("--json")]
        public bool Json { get; set; }
    }

    private sealed class IndexRecord
    {
        public ArtifactMeta? meta { get; set; }
        public string? dir { get; set; }
        public Counts? counts { get; set; }
    }
    private sealed class ArtifactMeta
    {
        public string? Subject { get; set; }
        public string? SubjectKind { get; set; }
        public DateTimeOffset GeneratedAt { get; set; }
        public string? GeneratorVersion { get; set; }
        public string? RunId { get; set; }
    }
    private sealed class Counts
    {
        public int AssessmentInfoCount { get; set; }
        public int AssessmentWarningCount { get; set; }
        public int AssessmentErrorCount { get; set; }
        public int RecommendationCount { get; set; }
        public int HostCount { get; set; }
        public int ResourceCount { get; set; }
    }

    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Deserialize")] 
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Deserialize")] 
    protected override Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var root = !string.IsNullOrWhiteSpace(settings.ArtifactsDir)
            ? settings.ArtifactsDir!
            : Path.Combine(Directory.GetCurrentDirectory(), "artifacts");

        if (!Directory.Exists(root))
        {
            AnsiConsole.MarkupLine($"[yellow]No artifacts directory found:[/] {root}");
            return Task.FromResult(0);
        }

        var records = new List<IndexRecord>();
        try
        {
            // If subject specified, read only that index
            if (!string.IsNullOrWhiteSpace(settings.Subject))
            {
                var safe = DomainDetective.Reports.FilePathHelper.MakeFileSafe(settings.Subject!);
                var idx = Path.Combine(root, safe, "index.jsonl");
                records.AddRange(ReadIndex(idx));
            }
            else
            {
                // Enumerate subject directories
                foreach (var dir in Directory.EnumerateDirectories(root))
                {
                    var idx = Path.Combine(dir, "index.jsonl");
                    if (!File.Exists(idx)) continue;
                    records.AddRange(ReadIndex(idx));
                }
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Failed to read artifacts:[/] {ex.Message}");
            return Task.FromResult(1);
        }

        // Sort by timestamp desc and take N
        var sorted = records
            .Where(r => r.meta != null)
            .OrderByDescending(r => r.meta!.GeneratedAt)
            .Take(Math.Max(1, settings.Count))
            .ToList();

        if (settings.Json)
        {
            var json = JsonSerializer.Serialize(sorted, DomainDetective.Helpers.JsonOptions.Default);
            Console.WriteLine(json);
            return Task.FromResult(0);
        }

        if (sorted.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No runs found.[/]");
            return Task.FromResult(0);
        }

        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Generated");
        table.AddColumn("Subject");
        table.AddColumn("Kind");
        table.AddColumn("Dir");
        table.AddColumn("Info/Warn/Error");
        foreach (var r in sorted)
        {
            var meta = r.meta!;
            var ts = meta.GeneratedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
            var counts = r.counts != null
                ? $"{r.counts.AssessmentInfoCount}/{r.counts.AssessmentWarningCount}/{r.counts.AssessmentErrorCount}"
                : "-";
            table.AddRow(ts, meta.Subject ?? "-", meta.SubjectKind ?? "-", r.dir ?? "-", counts);
        }
        AnsiConsole.Write(table);
        return Task.FromResult(0);
    }

    private static IEnumerable<IndexRecord> ReadIndex(string path)
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
            if (rec != null) yield return rec;
        }
    }
}
