using Spectre.Console;
using System;
using System.Collections;
using System.Linq;
using System.Text;
using System.Globalization;

namespace DomainDetective.CLI;

internal static class CliHelpers
{
    private static readonly IdnMapping _idn = new();
    /// <summary>
    ///     Adds property rows for <paramref name="obj"/> to <paramref name="table"/>.
    /// </summary>
    /// <param name="table">Target table instance.</param>
    /// <param name="obj">Object to inspect.</param>
    /// <param name="listAsString">Renders list values as comma separated strings when true.</param>
    private static string FormatString(string? value, bool unicode)
    {
        if (!unicode || string.IsNullOrEmpty(value))
        {
            return value ?? "null";
        }

        try
        {
            return _idn.GetUnicode(value);
        }
        catch (ArgumentException)
        {
            return value;
        }
    }

    internal static string ToAscii(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return domain ?? string.Empty;
        }

        try
        {
            return _idn.GetAscii(domain.Trim().Trim('.'));
        }
        catch (ArgumentException)
        {
            return domain;
        }
    }

    private static void AddProperties(Table table, object obj, bool listAsString = false, bool unicode = false)
    {
        if (obj == null)
        {
            return;
        }
        var properties = obj.GetType().GetProperties();
        foreach (var property in properties)
        {
            var value = property.GetValue(obj);
            if (value is IList listValue)
            {
                if (listAsString || value is byte[])
                {
                    var listString = string.Join(", ", listValue.Cast<object>());
                    table.AddRow(property.Name, FormatString(listString, unicode));
                }
                else
                {
                    var nested = new Table().Border(TableBorder.Rounded);
                    nested.AddColumn("Index");
                    nested.AddColumn("Value");
                    for (var i = 0; i < listValue.Count; i++)
                    {
                        nested.AddRow(i.ToString(), Markup.Escape(FormatString(listValue[i]?.ToString(), unicode)));
                    }
                    table.AddRow(new Markup(property.Name), nested);
                }
            }
            else if (value is IDictionary dictionaryValue)
            {
                var nested = new Table().Border(TableBorder.Rounded);
                nested.AddColumn("Key");
                nested.AddColumn("Value");
                foreach (DictionaryEntry entry in dictionaryValue)
                {
                    var key = Markup.Escape(entry.Key.ToString());
                    var val = Markup.Escape(FormatString(entry.Value?.ToString(), unicode));
                    nested.AddRow(key, val);
                }
                table.AddRow(new Markup(property.Name), nested);
            }
            else
            {
                var stringValue = value?.ToString();
                if (property.Name == "Mode" && stringValue is not null)
                {
                    var escaped = Markup.Escape(FormatString(stringValue, unicode));
                    if (stringValue.Equals("testing", StringComparison.OrdinalIgnoreCase) ||
                        stringValue.Equals("none", StringComparison.OrdinalIgnoreCase))
                    {
                        table.AddRow(Markup.Escape(property.Name), $"[yellow]{escaped}[/]");
                        continue;
                    }
                }
                table.AddRow(Markup.Escape(property.Name), Markup.Escape(FormatString(stringValue, unicode)));
            }
        }
    }

    /// <summary>
    ///     Renders the properties of <paramref name="data"/> inside a panel titled with <paramref name="title"/>.
    /// </summary>
    /// <param name="title">Panel header text.</param>
    /// <param name="data">Object, list or dictionary to display.</param>
    public static void ShowPropertiesTable(string title, object data, bool unicode = false)
    {
        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Property");
        table.AddColumn("Value");
        if (data is IDictionary dictionary)
        {
            foreach (DictionaryEntry entry in dictionary)
            {
                AddProperties(table, entry.Value, true, unicode);
            }
        }
        else if (data is IList list)
        {
            foreach (var item in list)
            {
                AddProperties(table, item, unicode: unicode);
            }
        }
        else
        {
            AddProperties(table, data, unicode: unicode);
        }
        var panel = new Panel(table)
        {
            Header = new PanelHeader(title),
            Expand = true
        };
        AnsiConsole.Write(panel);
    }

    internal static string? ReadLineRaw()
    {
        var builder = new StringBuilder();
        while (true)
        {
            var ch = Console.In.Read();
            if (ch == -1)
            {
                return builder.Length == 0 ? null : builder.ToString();
            }

            builder.Append((char)ch);
            if (ch == '\n')
            {
                break;
            }
            if (ch == '\r')
            {
                if (Console.In.Peek() == '\n')
                {
                    builder.Append((char)Console.In.Read());
                }
                break;
            }
        }

        return builder.ToString();
    }
}
