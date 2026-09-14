from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _prompt(name: str) -> str:
    return (ROOT / "prompts" / name).read_text().lower()


def test_titus_hunt_prompt_is_recall_first_and_poc_optional() -> None:
    prompt = _prompt("02-hunt.md")

    assert "recall-first" in prompt
    assert "proof of concept is optional" in prompt
    assert "confidence is diagnostic only" in prompt
    assert "source" in prompt and "guard" in prompt and "sink" in prompt


def test_openmythos_validation_does_not_steal_trace_decision() -> None:
    prompt = _prompt("03-validate.md")

    assert "do not reject solely because" in prompt
    assert "reachability stage" in prompt


def test_openmythos_trace_preserves_uncertainty() -> None:
    prompt = _prompt("06-trace.md")

    assert 'status = "uncertain"' in prompt
    assert "uncertainty, not proof of dead code" in prompt
