using System.Collections.Generic;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Aggregated recommendations across all analysis modules.
        /// </summary>
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(GetAllAssessments());

        /// <summary>
        /// Aggregated grouped recommendation views (by code), ordered by severity/category.
        /// </summary>
        public IReadOnlyList<RecommendationView> RecommendationViews => RecommendationEngine.GroupByCode(GetAllAssessments());

        /// <summary>
        /// Returns unique recommendations for all current assessments.
        /// </summary>
        public IReadOnlyList<RecommendationAdvice> GetRecommendations() => RecommendationEngine.From(GetAllAssessments());

        /// <summary>
        /// Returns grouped recommendation views (by code) for all current assessments.
        /// </summary>
        public IReadOnlyList<RecommendationView> GetRecommendationViews() => RecommendationEngine.GroupByCode(GetAllAssessments());
    }
}
