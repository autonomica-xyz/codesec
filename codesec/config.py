"""Load per-stage configuration from config/stages.yaml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class ModelProfile:
    name: str
    engine: str
    endpoint: str | None
    model: str
    source: str | None = None
    api_key_env: str | None = None
    temperature: float = 0.0
    max_output_tokens: int = 4096
    thinking: bool = False
    max_input_chars: int = 50_000
    context_limit: int = 32_768
    model_path: str | None = None
    model_path_env: str | None = None
    expected_sha256: str | None = None
    server_args: tuple[str, ...] = ()


def _classify_role(model: str) -> str:
    """Map a stage's model name to its role bucket (opus/sonnet/haiku).
    Used by apply_provider_models to swap entire model families while
    preserving the deliberate-disagreement opus/sonnet split."""
    m = (model or "").lower()
    if "opus" in m:
        return "opus"
    if "sonnet" in m:
        return "sonnet"
    if "haiku" in m:
        return "haiku"
    return ""


@dataclass
class StageConfig:
    name: str
    model: str
    concurrency: int
    tools: list[str]
    max_turns: int
    permission_mode: str
    repair_attempts: int
    profile: str | None = None
    # Review-panel size for validate (1 = classic single pass, >1 adds
    # an arbiter call). Meaningful only for validate; other stages ignore it.
    rounds: int = 1
    # Catch-all for per-stage feature knobs in stages.yaml (e.g.
    # `hints_in_hunt`, `policies`, `grade`). Unknown keys land here instead
    # of growing the dataclass for every experiment.
    options: dict = field(default_factory=dict)


@dataclass
class HarnessConfig:
    stages: dict[str, StageConfig] = field(default_factory=dict)
    model_profiles: dict[str, ModelProfile] = field(default_factory=dict)
    gapfill_iterations: int = 2
    feedback_iterations: int = 1

    def get(self, stage: str) -> StageConfig:
        try:
            return self.stages[stage]
        except KeyError:
            raise KeyError(
                f"Unknown stage {stage!r}. Known: {sorted(self.stages)}"
            ) from None

    def profile_for_stage(self, stage: str) -> ModelProfile | None:
        profile_name = self.get(stage).profile
        if profile_name is None:
            return None
        try:
            return self.model_profiles[profile_name]
        except KeyError:
            raise KeyError(
                f"Stage {stage!r} references unknown model profile "
                f"{profile_name!r}"
            ) from None

    def cap_concurrency(self, cap: int) -> None:
        """Mutate every stage's concurrency to min(current, cap). Useful
        for cost-contained test runs."""
        if cap < 1:
            raise ValueError("concurrency cap must be >= 1")
        for sc in self.stages.values():
            sc.concurrency = min(sc.concurrency, cap)

    def apply_provider_models(self, provider, explicit_model: str | None = None) -> None:
        """Remap every stage's model for a provider preset.

        - explicit_model (e.g. an Unsloth loaded GGUF, or --model) wins
          everywhere and collapses deliberate-disagreement to one model.
        - otherwise each stage keeps its role (opus/sonnet/haiku) but the
          *family* swaps to the provider's equivalents, so z.ai still gets
          validate(=glm-5.2) != hunt(=glm-4.7).
        - stages whose current model is already provider-native or has no
          role mapping are left untouched.
        """
        from codesec.providers import role_model  # avoid import cycle

        for sc in self.stages.values():
            if explicit_model:
                sc.model = explicit_model
                continue
            mapped = role_model(provider, sc.model)
            if mapped:
                sc.model = mapped


def load_config(path: Path | None = None) -> HarnessConfig:
    if path is None:
        path = Path(__file__).resolve().parent.parent / "config" / "stages.yaml"
    raw = yaml.safe_load(path.read_text())
    defaults = raw.get("defaults", {}) or {}
    profiles = {
        name: ModelProfile(
            name=name,
            engine=str(spec.get("engine", "local")),
            endpoint=spec.get("endpoint"),
            model=str(spec["model"]),
            source=spec.get("source"),
            api_key_env=spec.get("api_key_env"),
            temperature=float(spec.get("temperature", 0)),
            max_output_tokens=int(spec.get("max_output_tokens", 4096)),
            thinking=bool(spec.get("thinking", False)),
            max_input_chars=int(spec.get("max_input_chars", 50_000)),
            context_limit=int(spec.get("context_limit", 32_768)),
            model_path=spec.get("model_path"),
            model_path_env=spec.get("model_path_env"),
            expected_sha256=spec.get("expected_sha256"),
            server_args=tuple(str(arg) for arg in spec.get("server_args", [])),
        )
        for name, spec in (raw.get("model_profiles") or {}).items()
    }
    stages: dict[str, StageConfig] = {}
    for name, spec in (raw.get("stages") or {}).items():
        profile_name = spec.get("profile")
        if profile_name is not None and profile_name not in profiles:
            raise ValueError(
                f"stage {name!r} references unknown model profile "
                f"{profile_name!r}"
            )
        model = (
            profiles[profile_name].model
            if profile_name is not None
            else spec["model"]
        )
        _known_keys = {
            "model", "concurrency", "tools", "max_turns", "permission_mode",
            "repair_attempts", "profile", "rounds",
        }
        stages[name] = StageConfig(
            name=name,
            model=model,
            concurrency=int(spec["concurrency"]),
            tools=list(spec["tools"]),
            max_turns=int(spec.get("max_turns", defaults.get("max_turns", 25))),
            permission_mode=spec.get(
                "permission_mode", defaults.get("permission_mode", "acceptEdits")
            ),
            repair_attempts=int(
                spec.get("repair_attempts", defaults.get("repair_attempts", 1))
            ),
            profile=profile_name,
            rounds=max(1, int(spec.get("rounds", defaults.get("rounds", 1)))),
            options={
                k: v for k, v in spec.items() if k not in _known_keys
            },
        )
    loops = raw.get("loops", {}) or {}
    return HarnessConfig(
        stages=stages,
        model_profiles=profiles,
        gapfill_iterations=int(loops.get("gapfill_iterations", 2)),
        feedback_iterations=int(loops.get("feedback_iterations", 1)),
    )
