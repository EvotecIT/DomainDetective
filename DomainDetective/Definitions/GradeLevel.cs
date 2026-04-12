using System.ComponentModel;

namespace DomainDetective;

/// <summary>
/// Coarse letter grade for protocol and header posture.
/// </summary>
public enum GradeLevel
{
    /// <summary>Represents the unknown value.</summary>
    Unknown = 0,
    /// <summary>Failing posture with critical issues or misconfiguration.</summary>
    [Description("Failing: critical issues or misconfiguration")]
    F = 1,
    /// <summary>Weak posture with significant gaps or legacy support.</summary>
    [Description("Weak: significant gaps or legacy support")]
    D = 2,
    /// <summary>Adequate posture with baseline controls and recommended improvements.</summary>
    [Description("Adequate: baseline controls; improvements recommended")]
    C = 3,
    /// <summary>Good posture with secure configuration and minor gaps.</summary>
    [Description("Good: secure configuration with minor gaps")]
    B = 4,
    /// <summary>Excellent posture with strong modern configuration and best practices met.</summary>
    [Description("Excellent: strong modern configuration; best practices met")]
    A = 5
}

internal static class GradeLevelExtensions
{
    public static string ToLetter(this GradeLevel grade)
        => grade == GradeLevel.Unknown ? string.Empty : grade.ToString();

    public static string ToDisplay(this GradeLevel grade)
        => grade == GradeLevel.Unknown ? "Unknown" : $"{grade.ToLetter()} — {grade.GetDescription()}";

    public static bool IsAtLeast(this GradeLevel grade, GradeLevel threshold)
        => (int)grade >= (int)threshold;

    public static bool IsBelow(this GradeLevel grade, GradeLevel threshold)
        => (int)grade > 0 && (int)grade < (int)threshold;

    public static GradeLevel Min(GradeLevel a, GradeLevel b)
        => (int)a <= (int)b ? a : b;

    public static GradeLevel Max(GradeLevel a, GradeLevel b)
        => (int)a >= (int)b ? a : b;

    public static string GetDescription(this GradeLevel grade)
    {
        var mem = typeof(GradeLevel).GetMember(grade.ToString());
        if (mem.Length > 0)
        {
            var attr = (DescriptionAttribute[])mem[0].GetCustomAttributes(typeof(DescriptionAttribute), false);
            if (attr.Length > 0) return attr[0].Description;
        }
        return grade.ToString();
    }
}
