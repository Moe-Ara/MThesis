"""
Merge LoRA adapter into base model and export to GGUF for Ollama.

Usage:
    python -m intelligence.training.export_to_ollama \
        --adapter models/foundation-sec-scorer-lora \
        --output models/foundation-sec-scorer-gguf \
        --ollama-name foundation-sec-scorer

Requires: llama.cpp's convert_hf_to_gguf.py (pip install llama-cpp-python)
          or use the manual steps printed at the end.
"""

import argparse
import logging
import subprocess
import sys
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

BASE_MODEL = "fdtn-ai/Foundation-Sec-8B"


def merge_and_save(adapter_path: str, output_path: str, base_model: str = BASE_MODEL) -> None:
    """Merge LoRA adapter into base model and save as full model."""

    logger.info(f"Loading base model: {base_model}")
    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        torch_dtype=torch.float16,
        device_map="cpu",  # merge on CPU to avoid OOM
    )

    logger.info(f"Loading LoRA adapter: {adapter_path}")
    model = PeftModel.from_pretrained(model, adapter_path)

    logger.info("Merging LoRA weights into base model...")
    model = model.merge_and_unload()

    logger.info(f"Saving merged model to: {output_path}")
    model.save_pretrained(output_path, safe_serialization=True)

    tokenizer = AutoTokenizer.from_pretrained(adapter_path)
    tokenizer.save_pretrained(output_path)

    logger.info("Merged model saved.")


def convert_to_gguf(model_path: str, output_gguf: str, quantize: str = "q6_k") -> bool:
    """Try to convert to GGUF using llama.cpp's convert script."""
    try:
        # Try using llama-cpp-python's bundled converter
        result = subprocess.run(
            [sys.executable, "-m", "llama_cpp.convert", model_path, "--outfile", output_gguf, "--outtype", quantize],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            logger.info(f"GGUF file created: {output_gguf}")
            return True
        logger.warning(f"llama_cpp.convert failed: {result.stderr[:200]}")
    except Exception as e:
        logger.warning(f"GGUF conversion not available: {e}")

    return False


def create_modelfile(gguf_path: str, modelfile_path: str) -> None:
    """Create an Ollama Modelfile for the GGUF."""
    content = f"""FROM {gguf_path}

PARAMETER temperature 0.2
PARAMETER num_ctx 4096
PARAMETER stop "<|eot_id|>"

TEMPLATE \"\"\"<|begin_of_text|><|start_header_id|>system<|end_header_id|>

{{{{ .System }}}}<|eot_id|><|start_header_id|>user<|end_header_id|>

{{{{ .Prompt }}}}<|eot_id|><|start_header_id|>assistant<|end_header_id|>

\"\"\"

SYSTEM "You are a cybersecurity SOC analyst assistant. You respond only with valid JSON matching the requested schema."
"""
    Path(modelfile_path).write_text(content)
    logger.info(f"Modelfile created: {modelfile_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Export LoRA adapter to Ollama GGUF.")
    parser.add_argument("--adapter", type=str, required=True, help="Path to LoRA adapter directory.")
    parser.add_argument("--base-model", default=BASE_MODEL, help="Base model identifier.")
    parser.add_argument("--output", type=str, required=True, help="Output directory for merged model & GGUF.")
    parser.add_argument("--ollama-name", type=str, default=None, help="Ollama model name to register.")
    parser.add_argument("--quantize", default="q6_k", help="GGUF quantization type.")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Merge LoRA into base
    merged_path = output_dir / "merged"
    merge_and_save(args.adapter, str(merged_path), args.base_model)

    # Step 2: Convert to GGUF
    gguf_file = output_dir / f"foundation-sec-soar-{args.quantize}.gguf"
    converted = convert_to_gguf(str(merged_path), str(gguf_file), args.quantize)

    if converted:
        # Step 3: Create Modelfile
        modelfile = output_dir / "Modelfile"
        create_modelfile(str(gguf_file), str(modelfile))

        # Step 4: Register with Ollama
        if args.ollama_name:
            logger.info(f"Registering with Ollama as '{args.ollama_name}'...")
            result = subprocess.run(
                ["ollama", "create", args.ollama_name, "-f", str(modelfile)],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                logger.info(f"Model registered: ollama run {args.ollama_name}")
            else:
                logger.error(f"Ollama registration failed: {result.stderr[:200]}")
    else:
        print("\n" + "=" * 60)
        print("MANUAL GGUF CONVERSION STEPS:")
        print("=" * 60)
        print(f"1. Install llama.cpp: git clone https://github.com/ggerganov/llama.cpp")
        print(f"2. Convert: python llama.cpp/convert_hf_to_gguf.py {merged_path} --outtype {args.quantize}")
        print(f"3. Create Modelfile pointing to the .gguf file")
        print(f"4. Import: ollama create {args.ollama_name or 'my-soar-model'} -f Modelfile")
        print("=" * 60)


if __name__ == "__main__":
    main()
