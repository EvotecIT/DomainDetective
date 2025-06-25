using Spectre.Console;
using System;
using System.Collections;
using System.Linq;

namespace DomainDetective.Example {
    internal class Helpers {
        public static void ShowProperties(string analysisOf, object obj) {
            Console.WriteLine("----");
            Console.WriteLine($"Analysis of {analysisOf}:");
            var properties = obj.GetType().GetProperties();
            foreach (var property in properties) {
                var value = property.GetValue(obj);
                if (value is IList listValue) {
                    Console.WriteLine($"- {property.Name}:");
                    foreach (var item in listValue) {
                        Console.WriteLine($"  * {item}");
                    }
                } else {
                    Console.WriteLine($"- {property.Name}: {value}");
                }
            }
        }

        /// <summary>
        ///     Adds the properties of <paramref name="obj"/> to <paramref name="table"/>.
        /// </summary>
        /// <param name="table">Table instance to add rows to.</param>
        /// <param name="obj">Object whose properties will be read.</param>
        /// <param name="listAsString">When true, list values are rendered as comma separated strings.</param>
        private static void AddPropertiesTable(Table table, object obj, bool listAsString = false) {
            if (obj == null) {
                return;
            }
            var properties = obj.GetType().GetProperties();
            foreach (var property in properties) {
                var value = property.GetValue(obj);
                if (value is IList listValue) {
                    if (listAsString || value is byte[]) {
                        var listString = string.Join(", ", listValue.Cast<object>());
                        table.AddRow(property.Name, listString);
                    } else {
                        var nestedTable = new Table().Border(TableBorder.Rounded);
                        nestedTable.AddColumn("Index");
                        nestedTable.AddColumn("Value");

                        for (int i = 0; i < listValue.Count; i++) {
                            nestedTable.AddRow(i.ToString(), Markup.Escape(listValue[i]?.ToString() ?? "null"));
                        }

                        table.AddRow(new Markup(property.Name), nestedTable);

                    }
                } else {
                    if (value is IDictionary dictionaryValue) {
                        var nestedTable = new Table().Border(TableBorder.Rounded);
                        nestedTable.AddColumn("Key");
                        nestedTable.AddColumn("Value");

                        foreach (DictionaryEntry entry in dictionaryValue) {
                            var escapedKey = Markup.Escape(entry.Key.ToString());
                            var escapedValue = Markup.Escape(entry.Value?.ToString() ?? "null");
                            nestedTable.AddRow(escapedKey, escapedValue);
                        }
                        table.AddRow(new Markup(property.Name), nestedTable);
                    } else {
                        table.AddRow(Markup.Escape(property.Name), Markup.Escape(value?.ToString() ?? "null"));
                    }
                }
            }
        }

        /// <summary>
        ///     Displays a table of property names and values for the supplied object or list.
        /// </summary>
        /// <param name="analysisOf">Title shown in the output panel.</param>
        /// <param name="objs">Object, dictionary or list to inspect.</param>
        /// <param name="perProperty">Currently unused.</param>
        public static void ShowPropertiesTable(string analysisOf, object objs, bool perProperty = false) {
            var table = new Table();
            table.Border(TableBorder.Rounded);

            if (objs is IDictionary dictionary) {
                table.AddColumn("Property");
                table.AddColumn("Value");

                foreach (DictionaryEntry entry in dictionary) {
                    var obj = entry.Value;
                    var properties = obj.GetType().GetProperties();
                    foreach (var property in properties) {
                        var value = property.GetValue(obj);
                        if (value is IList listValue) {
                            var listString = string.Join(", ", listValue.Cast<object>());
                            table.AddRow(Markup.Escape($"{entry.Key}.{property.Name}"), Markup.Escape(listString));
                        } else {
                            table.AddRow(Markup.Escape($"{entry.Key}.{property.Name}"), Markup.Escape(value?.ToString() ?? "null"));
                        }
                    }
                }
            } else if (objs is IList list) {
                table.AddColumn("Property");
                table.AddColumn("Value");

                foreach (var obj in list) {
                    AddPropertiesTable(table, obj);
                }
            } else {
                table.AddColumn("Property");
                table.AddColumn("Value");
                AddPropertiesTable(table, objs);
            }

            var panel = new Panel(table)
                .Header($"Analysis of {analysisOf}")
                .Expand();

            AnsiConsole.Write(panel);
        }
    }
}