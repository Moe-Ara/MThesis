using System.Collections.Generic;
using Core.Interfaces;

namespace Core.NormalizationPipeline
{
    public sealed class BasicAlertValidator : IAlertValidator
    {
        public ValidationResult Validate(NormalizedAlert alert)
        {
            var errors = new List<string>();

            if (string.IsNullOrWhiteSpace(alert.AlertId))
                errors.Add("AlertId is required.");

            if (string.IsNullOrWhiteSpace(alert.SourceSiem))
                errors.Add("SourceSiem is required.");

            // Require at least one actionable entity (host/user/ip)
            var e = alert.Entities;
            var hasEntity =
                !string.IsNullOrWhiteSpace(e.Hostname) ||
                !string.IsNullOrWhiteSpace(e.HostId) ||
                !string.IsNullOrWhiteSpace(e.Username) ||
                !string.IsNullOrWhiteSpace(e.UserId) ||
                !string.IsNullOrWhiteSpace(e.SrcIp) ||
                !string.IsNullOrWhiteSpace(e.DstIp);

            if (!hasEntity)
                errors.Add("At least one entity must be present (host/user/ip).");

            return new ValidationResult(errors.Count == 0, errors);
        }
    }
}
