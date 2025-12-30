namespace Core.Interfaces;

public interface IAlertValidator
{
    ValidationResult Validate(NormalizedAlert alert);
}