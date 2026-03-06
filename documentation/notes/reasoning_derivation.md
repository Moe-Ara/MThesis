Reasoning Derivation (Planner Fallback)
======================================

If a planner returns no explicit reasoning, the system derives a structured
`reasoning` block in `intelligence/planners/plan_utils.py` (see `_build_reasoning`
and `sanitize_plan`). This keeps explanations consistent and audit-friendly.

Trigger
-------
- When the planner output lacks a `reasoning` object, `sanitize_plan` constructs
  one automatically (`source = "derived"`).
- If the planner *does* supply `reasoning`, it is passed through with
  `source = "model"` (and normalized if missing).

Inputs Used
-----------
1) **Assessment**
   - `hypothesis` becomes the reasoning summary (when present).
   - `evidence` (list) is used directly if provided.

2) **Entities (fallback evidence)**
   If assessment evidence is missing, the system falls back to entity values:
   - `srcIp`, `hostId`, `username`, `fileHash`, `processName`
   - Example: `src_ip=192.0.2.10`

3) **Policy + Safety Constraints**
   These are always included in the reasoning `constraints` list:
   - Actions limited to available entity values.
   - Max 4 actions enforced.
   - OpenTicket or Notify always included.
   - If assessment confidence < 0.60: only safe actions allowed.

4) **Action Justifications**
   Each action gets a short rationale. If the planner didn’t provide one, the
   system uses a default mapping:
   - BlockIp → “Block the source IP to stop continued malicious traffic.”
   - IsolateHost → “Isolate the host to prevent lateral movement during investigation.”
   - DisableUser → “Disable the user account to prevent credential abuse.”
   - KillProcess → “Terminate the suspicious process to halt malicious activity.”
   - QuarantineFile → “Quarantine the file to prevent execution while preserving evidence.”
   - CollectForensics → “Collect forensics to preserve evidence and confirm scope.”
   - Notify → “Notify the SOC team to coordinate investigation.”
   - OpenTicket → “Create an auditable record for analyst review.”
   - Rollback actions use rollback-specific defaults where applicable.

Output Shape
------------
The derived reasoning matches this schema:

{
  "source": "derived",
  "summary": "<assessment hypothesis or strategy summary>",
  "evidence": [ "<item1>", "<item2>", ... ],
  "constraints": [ "<constraint1>", "<constraint2>", ... ],
  "action_justifications": {
    "ActionType": "Justification text",
    ...
  }
}

Where It Is Stored
------------------
- Returned in the plan JSON as `plan.reasoning`.
- Mirrored into the engine as a tag in `plan.tags["planner_reasoning"]` by
  `NetCore/Core/Planning/HttpPlannerClient.cs` for UI display.

Why This Matters
----------------
Even with lightweight planners (or rule-based planners), the system always
produces a consistent explanation trail. That keeps the demo deterministic and
thesis-ready without requiring LLM reasoning for every run.
