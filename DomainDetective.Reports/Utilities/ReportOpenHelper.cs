using System;
using System.Diagnostics;

namespace DomainDetective.Reports;

public static class ReportOpenHelper
{
    public static void TryOpen(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        try
        {
            var psi = new ProcessStartInfo { FileName = path, UseShellExecute = true };
            Process.Start(psi);
        }
        catch
        {
            // Best-effort open; ignore failures.
        }
    }
}
