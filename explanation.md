## My Two-Week Work: Teaching Ollama to Write Wazuh Rules

Every file in the repo ties into that story; the sections below recreate the timeline I can walk through with the professor.

---

### Week 1 – Build the labeled data foundation

1. **`data/dataset.csv`**
   - Produced by running `dataset_builder.py` over the archive files. The script flattens each event, extracts metadata (like `mitre`, `groups`, `description`, `win.eventdata`, etc.), de-duplicates the rows, and normalizes them into the same CSV schema.
   - That CSV lets me reference rows by `dataset_id` when crafting an annotation. In the demo I can point to a handful of rows, show how I filtered out noisy alerts (e.g., legitimate Explorer launches), and explain why I chose specific IDs for the gaps I wanted to annotate.

2. **`training_annotations.json`**
   - This is the manual list of detection gaps. Each entry records a `dataset_id`, a concise `detection_goal`, and the `<group><rule>...</rule></group>` XML snippet describing the ideal rule.
   - Writing these entries forces me to reason about the log context, define the goal, and sketch the rule. Showing a few entries proves I wasn’t guessing — every prompt has a documented rationale.

3. **`training_data_builder.py` → `training_data.jsonl`**
   - Running `python training_data_builder.py --dataset data/dataset.csv --annotations training_annotations.json --output training_data.jsonl` emits the prompt/completion JSONL.
   - The builder looks up each annotated row, formats the relevant fields into a human-readable prompt, and pairs it with the annotated XML completion. The resulting file is the single source of truth for any future fine-tuning or augmentation step.

4. **`generate_annotation_logs.py` → `data/annotation_logs/*.json`**
   - This script regenerates lightweight JSON logs for each annotation. It loads the annotated row, truncates the verbose `full_log` field to keep prompts under ~4,096 tokens, and writes one JSON file per gap.
   - Those per-gap logs become the `example_events` payload that the optimizer consumes. Regenerating them after every annotation makes the pipeline repeatable, so I can mention that the whole data setup is reproducible on demand.

5. **`data/local_rules.xml`**
   - This is the working rule set. The optimizer sends it as `existing_rules` so the LLM understands what already exists, avoids duplicate IDs, and aligns naming conventions before proposing new detections.
   - I can explain that keeping this file updated by hand is part of the workflow, and including it in the prompt prevents the model from overwriting existing logic.

---

### Week 2 – Automate prompt feeding and inference

6. **`wazuh_rule_optimizer.py`**
   - This CLI loads the detection goal, existing rules, and the trimmed log, then sends everything to `WazuhRuleAgent`. The new `--mode` flag lets me choose between:
     - `online` (default): talk to Ollama via the HTTP client.
     - `offline`: load the locally fine-tuned LoRA adapter (`wazuh-specialized`) and run the same prompt through a transformers-based client.
   - Additional flags (`--adapter-path`, `--offline-base-model`, `--offline-max-new-tokens`, `--offline-temperature`) let me control which weights and sampling settings the offline path uses. I can demo both flows with a single CLI line so it’s clear the same prompt logic powers both Unity paths.

7. **`wazuh_rule_agent.py`**
   - Holds `WAZUH_RULE_SYSTEM_PROMPT` and builds the payload dictionary (`detection_goal`, `example_events`, `existing_rules`, `existing_logs`). Both the online and offline clients reuse this prompt, so the output schema stays identical.

8. **`llm_client.py`**
   - Sends the system prompt and serialized payload to `http://localhost:11434/api/chat`, handles empty/non-JSON responses, and returns the parsed JSON object (`rule_xml`, `explanation`, `tuning_suggestions`, `test_plan`).
   - Mentioning this module shows that Week 2 automates the entire interaction with Ollama instead of pasting logs into the chat manually.

---

### Week 2.5 – Fine-tuning and offline deployment

9. **`train_mistral_lora.py`**
   - Fine-tunes a LoRA adapter against `training_data.jsonl`. I ran the script with `--model Qwen/Qwen2.5-3B` and the JSONL to produce `wazuh-specialized`.
   - The training code saves both the adapter (`adapter_model.safetensors`, `adapter_config.json`) and the tokenizer (JSON + vocab files) so inference can reuse them later.

10. **`wazuh-specialized`**
    - Contains the trained LoRA adapter and tokenizer files. `LocalLlmClient` loads these assets, pairs them with the same base model (`Qwen/Qwen2.5-3B` by default), and reuses the `WAZUH_RULE_SYSTEM_PROMPT`.
    - Because the offline client uses `PeftModel.from_pretrained(base, adapter_path)`, it can answer the prompt without hitting Ollama at all. In the presentation I can mention that the same prompt is running both through Ollama and through these local weights.

11. **`training_data.jsonl` (again)**
    - Besides being the training input, it is the file I can use to sanity-check the offline path — feeding a prompt from the JSONL should produce the annotated rule XML.
    - This ties Week 1’s documentation work directly into the Week 2.5 fine-tuning/deployment story.

---

With these artifacts I can narrate two full workflows during the presentation:

- `python wazuh_rule_optimizer.py --mode online --rules data/local_rules.xml --logs data/annotation_logs/<id>.json --detection-goal "..."` (Ollama API path).
- `python wazuh_rule_optimizer.py --mode offline --adapter-path wazuh-specialized --offline-base-model Qwen/Qwen2.5-3B (...)` (local LoRA path).

The professor can see the project spans from data engineering through automation, fine-tuning, and deployment — exactly the two-week effort the course asked for.
