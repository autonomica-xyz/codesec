from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _script(relative: str) -> str:
    return (ROOT / relative).read_text()


def test_probe_launcher_is_owned_repeatable_and_fail_closed():
    script = _script("bench/probe/probe_model.sh")

    assert "pkill -f" not in script
    assert "--repeats" in script
    assert "--attempts" in script
    assert "--thinking disabled" in script
    assert "--metadata-json" in script
    assert "LLAMA_PORT" in script
    assert '--base-url "http://127.0.0.1:${LLAMA_PORT}"' in script
    assert "trap cleanup EXIT" in script


def test_direct_gguf_probe_is_pinned_fully_offloaded_and_tmpfs_scoped():
    script = _script("bench/probe/probe_gguf.sh")

    assert "pkill -f" not in script
    assert 'mktemp -d "/dev/shm/codesec-probe-${SUFFIX}.' in script
    assert 'GPU_LAYERS="${GPU_LAYERS:-999}"' in script
    assert 'GGML_BACKEND_PATH="${GGML_BACKEND_PATH:-$CUDA_BACKEND}"' in script
    assert 'LD_LIBRARY_PATH="$CUDA_LIBRARY_DIR' in script
    assert "CUDA/full-offload gate failed" in script
    assert "--query-compute-apps=pid,used_memory" in script
    assert '--revision "$MODEL_REVISION"' in script
    assert '--requested-model "${MODEL_REPO}@${MODEL_REVISION}:${MODEL_FILE}"' in script
    assert '--thinking "$THINKING"' in script
    assert '--metadata-json "$META"' in script
    assert "trap cleanup EXIT" in script


def test_current_sweep_uses_expected_highest_practical_quants_and_safe_speculation():
    script = _script("bench/probe/run_current_sweep.sh")

    assert "Qwopus3.6-27B-v2-MTP-Q8_0.gguf" in script
    assert "SPEC_TYPE=draft-mtp" in script
    assert "OpenMythos-27B-Q6_K.gguf" in script
    assert "SPEC_TYPE=ngram-mod" in script
    assert "SWA_CHECKPOINTS=5" in script
    assert "Titus-CybersecurityLLM-v1.0.Q4_K_M.gguf" in script
    assert "CyberPal2.0-20B.Q6_K.gguf" in script


def test_runtime_metadata_records_builds_and_loaded_vram():
    source = _script("bench/probe/runtime_metadata.py")

    assert "unsloth_cli_version" in source
    assert "llama_server_version" in source
    assert "memory.used" in source
    assert "server_port" in source


def test_corpus_launcher_uses_clean_read_only_copy_and_scores_final_report():
    script = _script("bench/corpus/run_agent.sh")

    assert "pkill -f" not in script
    assert "mktemp -d" in script
    assert "chmod -R a-w" in script
    assert "ground_truth.json" in script
    assert "score_repo.py" in script
    assert "LLAMA_PORT" in script
    assert '--base-url "http://127.0.0.1:${LLAMA_PORT}"' in script
    assert "trap cleanup EXIT" in script


def test_duo_corpus_launcher_runs_one_gpu_schedule_and_stage_scoring():
    script = _script("bench/corpus/run_duo.sh")

    assert "pkill -f" not in script
    assert "CODESEC_TITUS_GGUF" in script
    assert "CODESEC_OPENMYTHOS_GGUF" in script
    assert "--pipeline duo-v1" in script
    assert "--runtime managed" in script
    assert "--run-root" in script
    assert "chmod -R a-w" in script
    assert "SOURCE_SHA256" in script
    assert "FINAL_SHA256" in script
    assert "--stages" in script
    assert "trap cleanup EXIT" in script
