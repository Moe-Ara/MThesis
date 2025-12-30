## Planner module – extending actions and strategies

The planner is composed of small, replaceable parts:

- `IStrategySelector` decides the high-level strategy (ObserveMore, Contain, etc.).
- `IActionSelector` chooses ordered actions based on entities and strategy.
- `IRiskEstimator` computes risk/impact for each action.
- `IRollbackBuilder` generates rollback steps for reversible actions.
- `IActionNormalizer` removes duplicates and keeps ordering deterministic.

To add a new action:

1. Add the enum value in `ActionType` (`NetCore/Core/DTOs.cs`).
2. Add an `ActionDefinition` to `ActionCatalogDefaults.CreateDefault()`.
3. Update `BasicActionSelector` with entity requirements + ordering rules.
4. Update `BasicRollbackBuilder` if the action is reversible.

To add a new strategy:

1. Add the enum value in `PlanStrategy` (`NetCore/Core/DTOs.cs`).
2. Update `BasicStrategySelector` with the selection logic.
3. Update `BasicActionSelector` to map the strategy to actions.

All components are constructor-injected in `Planner`, so alternative implementations can be swapped in without changing the rest of the pipeline.
