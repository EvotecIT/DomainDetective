using Spectre.Console;
using System;
using System.Collections;
using System.Linq;

namespace DomainDetective.CLI;

internal static class CliHelpers
{
    private static void AddProperties(Table table, object obj, bool listAsString = false)
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
                    table.AddRow(property.Name, listString);
                }
                else
                {
                    var nested = new Table().Border(TableBorder.Rounded);
                    nested.AddColumn("Index");
                    nested.AddColumn("Value");
                    for (var i = 0; i < listValue.Count; i++)
                    {
                        nested.AddRow(i.ToString(), Markup.Escape(listValue[i]?.ToString() ?? "null"));
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
                    var val = Markup.Escape(entry.Value?.ToString() ?? "null");
                    nested.AddRow(key, val);
                }
                table.AddRow(new Markup(property.Name), nested);
            }
            else
            {
                table.AddRow(Markup.Escape(property.Name), Markup.Escape(value?.ToString() ?? "null"));
            }
        }
    }

    public static void ShowPropertiesTable(string title, object data)
    {
        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Property");
        table.AddColumn("Value");
        if (data is IDictionary dictionary)
        {
            foreach (DictionaryEntry entry in dictionary)
            {
                AddProperties(table, entry.Value, true);
            }
        }
        else if (data is IList list)
        {
            foreach (var item in list)
            {
                AddProperties(table, item);
            }
        }
        else
        {
            AddProperties(table, data);
        }
        var panel = new Panel(table)
        {
            Header = new PanelHeader(title),
            Expand = true
        };
        AnsiConsole.Write(panel);
    }
}
