using Spectre.Console;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
                        //table.AddColumn(property.Name);


                        var value = property.GetValue(obj);
                        if (value is IList listValue) {
                            var listString = string.Join(", ", listValue.Cast<object>());
                            table.AddRow($"{entry.Key}.{property.Name}", listString);
                        } else {
                            table.AddRow($"{entry.Key}.{property.Name}", value?.ToString() ?? "null");
                        }
                    }
                }
            } else if (objs is IList list) {
                table.AddColumn("Property");
                table.AddColumn("Value");

                foreach (var obj in list) {
                    var properties = obj.GetType().GetProperties();
                    foreach (var property in properties) {
                        var value = property.GetValue(obj);
                        if (value is IList listValue) {
                            var listString = string.Join(", ", listValue.Cast<object>());
                            table.AddRow(property.Name, listString);
                        } else {
                            table.AddRow(property.Name, value?.ToString() ?? "null");
                        }
                    }
                }
            } else {
                if (perProperty == false) {
                    table.AddColumn("Property");
                    table.AddColumn("Value");

                    var properties = objs.GetType().GetProperties();
                    foreach (var property in properties) {
                        var value = property.GetValue(objs);
                        if (value is IList listValue) {
                            var nestedTable = new Table().Border(TableBorder.Rounded);
                            nestedTable.AddColumn("Index");
                            nestedTable.AddColumn("Value");
                            for (int i = 0; i < listValue.Count; i++) {
                                nestedTable.AddRow(new Markup(i.ToString()), new Markup(listValue[i]?.ToString() ?? "null"));
                            }
                            table.AddRow(new Markup(property.Name), nestedTable);
                        } else {
                            table.AddRow(property.Name, value?.ToString() ?? "null");
                        }



                    }
                } else {
                    var properties = objs.GetType().GetProperties();
                    foreach (var property in properties) {
                        table.AddColumn(property.Name);
                    }

                    var row = new List<string>();
                    foreach (var property in properties) {
                        var value = property.GetValue(objs);
                        if (value is IList listValue) {
                            var listString = string.Join(", ", listValue.Cast<object>());
                            row.Add(listString);
                        } else {
                            row.Add(value?.ToString() ?? "null");
                        }
                    }
                    table.AddRow(row.ToArray());
                }
            }

            var panel = new Panel(table)
                .Header($"Analysis of {analysisOf}")
                .Expand();

            AnsiConsole.Write(panel);
        }
    }
}
