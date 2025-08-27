using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Aggregated assessments collected from all analyses that expose them.
        /// Auto-discovers public properties implementing IHasAssessments.
        /// </summary>
        public IEnumerable<Assessment> GetAllAssessments() {
            foreach (var pi in _assessmentProps.Value) {
                object value;
                try { value = pi.GetValue(this); } catch { continue; }
                if (value is IHasAssessments has && has.Assessments != null) {
                    foreach (var a in has.Assessments) yield return a;
                }
            }
        }

        private static readonly Lazy<PropertyInfo[]> _assessmentProps = new Lazy<PropertyInfo[]>(() =>
            typeof(DomainHealthCheck)
                .GetProperties(BindingFlags.Instance | BindingFlags.Public)
                .Where(p => typeof(IHasAssessments).IsAssignableFrom(p.PropertyType))
                .ToArray()
        );
    }
}
