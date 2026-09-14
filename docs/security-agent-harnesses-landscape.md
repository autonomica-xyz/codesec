# Pentesting and code-security agent harnesses: landscape report

**Date:** 2026-09-13  
**Scope:** Open-source (and notable closed) agent *harnesses* for penetration testing, vulnerability hunting, and source-code security review. GitHub repos are the primary artifact; X/Twitter, papers, leaderboards, and vendor docs are used as corroboration.  
**How to use this:** start with §1–§2, then jump to the catalog in §10. Star counts are snapshots from roughly 2026-09-02 to 2026-09-13 and move fast.

---

## 1. What “good” means here

A **security agent harness** is everything around the model: the loop, tools, sandbox, prompts/skills, shared state, verification gates, and evals. Cloudflare’s formulation (after scaling one across its own fleet) is the useful one: *the harness is the bit that lasts*. The model finds plausible bugs; the harness is what throws most of them away before a human sees them.

Three product shapes dominate:

| Shape | What it is | Typical proof | Examples |
|---|---|---|---|
| **White-box AppSec pentester** | Reads source, maps attack surface, exploits the running app | Working PoC / flag / SARIF | Shannon, Strix, Visa VVAH |
| **Black-box / infra pentester** | Scope + tools + Docker Kali; no (or little) source | Flag, shell, attack-graph edge | PentAGI, PentestAgent, ARTEMIS, Tsecbench teams |
| **Code-audit pipeline** | Multi-stage SAST-with-an-LLM: hunt → disprove → reachability → patch | Crash, taint trace, adversarial re-read | Anthropic Defending Code, Google Mantis, evilsocket/audit, Cloudflare skill |

A fourth layer is **not a harness at all**: skill packs and MCP servers that hitch a ride on Claude Code / Codex / Pi / Cursor. Those are methodology + tools, not an agent loop. They are listed separately because they are currently the fastest-growing distribution channel.

**Caveats that apply to every score in this document**

- **Stars ≠ quality.** Strix and Shannon are the public face of the field; Tsecbench winners and AIxCC CRS systems are the engineering face. AppSec Santa’s 2026 survey of 39 agents is explicit on this.
- **XBOW-104 numbers are not comparable** unless the write-up states black-box vs white-box, single-shot vs best-of-N, and whether traces are published. Several 99–104/104 claims are marketing; RedAmon’s 101/104 with public transcripts is the current high-water mark among *reproducible black-box* results.
- **Lab-to-real gap is large.** GPT-4-class agents exploited ~87% of one-day CVEs *when given the CVE description*, and ~13% of realistic CVE-Bench cases (hierarchical T-Agent, success@5). On SEC-bench, SOTA code agents hit at most **18% PoC generation** and **34% patching**. CyberGym’s best non-thinking combo (OpenHands + Claude Sonnet 4) is **17.9%** on 1,507 real OSS-Fuzz bugs. Hard HackTheBox remains near zero for most open agents. Tsecbench hosted scores look saturated at the top (97.14 → 93.47 for ranks 1–5) because that board is a different, easier-looking mix than academic long-horizon suites.
- **Sandbox claims need a close read.** Visa VVAH’s default profile does not compile, execute, or grant Bash (optional S6 HTTP only to localhost). Capital One VulnHunter’s verifier is read-only, no Bash/network. Anthropic defending-code and Mantis reproducers use gVisor. evilsocket/audit Hunt agents **have Bash and are not OS-sandboxed** — same gap codesec still has. RAPTOR uses Semgrep/CodeQL plus Linux namespaces, Landlock, and seccomp.
- Use only on systems you own or are authorized to test. Several of these wrap Metasploit, sqlmap, and live browsers.

---

## 2. Best starting points (indexes)

If you only clone a handful of repos, clone these first. They are maps, not products.

| Repo | What it is | Why it matters |
|---|---|---|
| [Ed-Marcavage/awesome-security-agent-harnesses](https://github.com/Ed-Marcavage/awesome-security-agent-harnesses) | Curated harness / sandbox / MCP / eval list, with a precise definition of “harness” | Best English-language taxonomy; splits code-audit vs pentest vs fuzzing vs AIxCC |
| [Yeti-791/Awesome-Offensive-AI-Agentic-Landscape](https://github.com/Yeti-791/Awesome-Offensive-AI-Agentic-Landscape) | 46 agents, 11 models, 3 skill packs, 7 MCP servers, 116 papers, 13 benches, 32 commercial products. Snapshot 2026-09-11 | Best star-ranked catalog; TCH/Tsecbench-aware; Chinese + English |
| [Yeti-791/Tsec-Hackathon](https://github.com/Yeti-791/Tsec-Hackathon) | Official Tencent Cloud Intelligent Penetration Hackathon archive (PPTs, videos, top-20 repos) | The densest cluster of *working* pentest harnesses outside the US lab scene |
| [scadastrangelove/awesome-ai-security-tools](https://github.com/scadastrangelove/awesome-ai-security-tools) | Broader AI-security tooling (agent security, SCA, SOC, RE, LLM red-team) | Complements the two lists above; includes “securing the agent” as well as “agent as attacker” |
| [EvanThomasLuke/Awesome-AI-Hacking-Agents](https://github.com/EvanThomasLuke/Awesome-AI-Hacking-Agents) | AI hacking agents + AIxCC finalists + commercial + papers | Good AIxCC + product overlay |
| [fr0gger/Awesome-GPT-Agents](https://github.com/fr0gger/Awesome-GPT-Agents) | Older, still-cited GPT-agents list (~6.6k stars) | Historical baseline (2023–24 wave) |
| [raphabot/awesome-cybersecurity-agentic-ai](https://github.com/raphabot/awesome-cybersecurity-agentic-ai) | MCP / tools / frameworks / papers / community | Tooling-centric |
| [simon-p-j-r/LLM4Pentest](https://github.com/simon-p-j-r/LLM4Pentest) | Paper corpus (~108 classified papers) used to audit the Yeti-791 list | Literature backbone |

Tsecbench hosted leaderboard (not a GitHub repo): [tsecbench.zc.tencent.com](https://tsecbench.zc.tencent.com/). As of 2026-09-11 the official Tsecbench v1 board was led by **Cairn_Y** (97.14), **Miko** (95.19), **Hiveptagi** (93.91), **CyberPenda** (93.82), **RiftX** (93.47). DeepSeek V4 / V4.1 Flash dominate the model column.

---

## 3. Production-grade open pentest agents

These are the projects people actually run. Ordered by a mix of stars, maintenance, and independent eval signal — not stars alone.

### 3.1 The two public giants

**[usestrix/strix](https://github.com/usestrix/strix)** — 62,148 stars (GitHub API, this research), Apache-2.0, Python.  
Autonomous “AI hackers”: Kali Docker runtime, **Caido HTTP proxy**, browser, terminal, Python exploit runtime, multi-agent graph (recon / exploit / validate). Findings are supposed to ship with a working PoC, not a scanner maybe. CLI + GitHub Actions + `npx skills add usestrix/strix` for Claude Code / Cursor. Model-agnostic via LiteLLM.  
X discourse (Aug–Sep 2026) treats Strix as the default open-source name: +10k stars in a week at one point, “agents that pentest your app and prove it.” Independent eval (Ethiack, 2026) found **high precision, lower recall** versus PentAGI — it reports fewer, cleaner findings.  
**Use when:** you want a developer-first AppSec agent you can drop on a repo or URL.

**[KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon)** — 47,956 stars (GitHub API, this research), AGPL-3.0, TypeScript.  
White-box web/API pentester: source-aware recon → vuln analysis → live exploitation → evidence → PDF/SARIF. Shannon 2.0 replaced a closed agent SDK with the **Pi harness** ([earendil-works/pi](https://github.com/earendil-works/pi), ~104k stars — a general coding-agent runtime, not a pentest tool). Shannon 3.0 (Sep 2026) added a multi-stage agentic SAST pipeline adapted from Google Mantis, resumable workspaces, GitHub Action / GitLab CI, native SARIF 2.1. Keygraph’s own XBOW claim is 100/104 on a *modified hint-free fork with white-box source* — not a black-box number. Fortune-500 internal-app usage is claimed by the vendor.  
**Use when:** you have source *and* a running staging instance, and you want CI-shaped output.

### 3.2 Serious self-hosted pentest systems

| Repo | Stars (approx) | Lang | Architecture | Notes |
|---|---|---|---|---|
| [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi) | 23.6k | Go | Fully autonomous multi-agent; Docker sandbox; 20+ tools (nmap, Metasploit, sqlmap); web control plane; Langfuse | Repeatedly cited as the “self-host the whole red team” option. MIT. Still trending on X in Sep 2026 |
| [GreyDGL/PentestGPT](https://github.com/GreyDGL/PentestGPT) | 15,450 | Python | v1.0 drives Claude Code or Codex in Docker through CTF or pentest pipelines; legacy three cooperating LLM sessions (reasoning / generation / parsing) on a Pentesting Task Tree | USENIX Security 2024 founding paper ([arXiv:2308.06782](https://arxiv.org/abs/2308.06782)). Historical baseline, not SOTA autonomy |
| [0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai) | 11,850 | Python | MCP server by OTT Cybersecurity; 150+ tools + 12+ workflow agents (BugBountyWorkflowManager, CTFWorkflowManager) | Tool belt more than a closed loop. Popular on X as “give Claude Metasploit” |
| [aliasrobotics/cai](https://github.com/aliasrobotics/cai) | 9.8k | Python | Cybersecurity AI framework, 300+ LLMs, specialized agents (red team, bug bounty, forensics, OT/robotics) | **Archived 2026-08-28.** 18 papers, claimed 30+ CVEs, NeuroGrid CTF 41/45 as Q0FJ. Successor stack is Alias CSI (closed) wrapping Claude Code / Codex / CAI |
| [Ed1s0nZ/CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI) | 6.3k | Go | AI-native security testing platform | TCH season-1 high-star project |
| [elder-plinius/T3MP3ST](https://github.com/elder-plinius/T3MP3ST) | 5.9k | TypeScript | Meta-harness: reuse local coding agents (Claude Code / Codex / Ollama) as 0-day hunters | Distinct idea: don’t write a new agent, *steer* the ones you already run |
| [GH05TCREW/pentestagent](https://github.com/GH05TCREW/pentestagent) | 3.0k | Python | Black-box, RAG, Kali tools, autonomous + multi-agent modes | AsiaCCS 2025 paper ([arXiv:2411.05185](https://arxiv.org/abs/2411.05185)). Recurring X shares |
| [oritera/Cairn](https://github.com/oritera/Cairn) | 2.5k | Python | General state-space search; equal workers; blackboard + ant-colony; no hardcoded roles | TCH S2 3rd, **only full-AK**. Tsecbench v1 #1 as Cairn_Y (97.14) as of 2026-09-11 |
| [samugit83/redamon](https://github.com/samugit83/redamon) | 2.4k | Python | Recon → exploit → post-exploit over a Neo4j attack graph; then triage, patch, PR | **101/104 XBOW black-box with published transcripts** — the most credible public XBOW result |
| [Armur-Ai/Pentest-Swarm-AI](https://github.com/Armur-Ai/Pentest-Swarm-AI) | 2.5k | Go | Stigmergic blackboard (pheromones); agents wake by finding-weight, not a fixed pipeline | Positions itself as “real swarm, not a sequential multi-agent.” README caveat: swarm scheduler is **alpha**; default runner is still a sequential 5-phase pipeline |
| [0xSteph/pentest-ai](https://github.com/0xSteph/pentest-ai) | 1.6k | Python | MCP + CLI; 205+ tools; **machine oracles re-run every exploit**; proof capsules | Verification-first design. Companion [0xSteph/pentest-ai-agents](https://github.com/0xSteph/pentest-ai-agents) (Claude Code subagents, ~2.2k) |
| [SanMuzZzZz/LuaN1aoAgent](https://github.com/SanMuzZzZz/LuaN1aoAgent) | 1.3k | Python | State-aware + causal-reasoning autonomous pentest | TCH S1 3rd (Guangzhou University). Claimed XBOW >90% |
| [PentesterFlow/agent](https://github.com/PentesterFlow/agent) | 1.3k | TypeScript | Human-in-the-loop terminal agent; OWASP Top 10 skills; Burp; coverage tracking | Operator stays in control |
| [ipa-lab/hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT) | 1.2k | Python | ~50-line agent kits + Linux privesc benchmarks | TU Wien research line (Happe/Cito). Honest evals, small surface |
| [PwnKit-Labs/pwnkit](https://github.com/PwnKit-Labs/pwnkit) | (active; `npx pwnkit-cli`) | TypeScript | Shell-first, minimal tools, 11-layer triage, **blind re-exploitation by a second agent** | Claims 99–103/104 on retained XBOW artifacts. Also covers LLM apps and npm supply chain. Treat the number as vendor-reported; the *architecture* (second-agent re-exploit) is the transferable idea |
| [Stanford-Trinity/ARTEMIS](https://github.com/Stanford-Trinity/ARTEMIS) | 540 | Python | Supervisor + spawned Codex subagents | ICLR 2026 paper: beat **9 of 10 human pentesters** on a live 8,000-host enterprise net at ~$18/hour, 82% valid-submission rate ([arXiv:2512.09882](https://arxiv.org/abs/2512.09882)) |

### 3.3 Newer / smaller harnesses that are conceptually interesting

| Repo | Why look |
|---|---|
| [S1N6H/pentest-harness](https://github.com/S1N6H/pentest-harness) | Self-hosted BYOK workspace (fork/rebrand of DeepSeek Harness). Plugin layers for model, tools, sessions, credentials. JSONL/SQLite persistence, compaction. Viral on X late Aug 2026 (@Dinosn, 1k likes / 1.3k bookmarks). Architecture comment that stuck: *scope gates belong in the harness, not the prompt* |
| [N0tMilk/prometheus-pentest-harness](https://github.com/N0tMilk/prometheus-pentest-harness) | Bootstrapper that emits `AGENTS.md` + skills + Obsidian vault. Enforces evidence-driven workflow and attack-chain thinking rather than running tools |
| [omemishra/Hacker-Harness](https://github.com/omemishra/Hacker-Harness) | Authorization-aware; deterministic execution + strict scope gates + Caido + HackerOne/Bugcrowd report formats |
| [wudidike/pentest_skill](https://github.com/wudidike/pentest_skill) | Black-box web pentest *skill*: Intake → Recon → Enum → Hunt → Report with checkpoints; 19 playbooks, 305 payloads, H1 cases loaded on demand |
| [H-mmer/pentest-agents](https://github.com/H-mmer/pentest-agents) | 48+ skills for Claude Code / Codex / Gemini / Cursor / Windsurf / Copilot / OpenClaw |
| [s0ld13rr/pentestcode](https://github.com/s0ld13rr/pentestcode) | Hard fork of OpenCode, stripped of code-editing, rebuilt for offense. Lead strategist + specialist subagents over a relationship graph. Circulating on X Sep 2026 |
| [lordx64/pentestkit](https://github.com/lordx64/pentestkit) | Claims 104/104 XBOW with Kimi K3. **No published traces found in this research** — treat as unverified |
| [stuxlabs/AWE](https://github.com/stuxlabs/AWE) | NDSS 2026: memory-augmented, vuln-specific pipelines on XBOW |
| [arthurgervais/mapta](https://github.com/arthurgervais/mapta) | MAPTA, arXiv:2508.20816, XBOW 76.9%, 10 findings into CVE review |
| [KHenryAegis/VulnBot](https://github.com/KHenryAegis/VulnBot) | PTG (penetration task graph), arXiv:2501.13411 |
| [andreashappe/cochise](https://github.com/andreashappe/cochise) | Autonomous assumed-breach AD (TOSEM 2025 / arXiv:2502.04227) |
| [uiuc-kang-lab/HPTSA](https://github.com/uiuc-kang-lab/HPTSA) | Supervisor + specialized subagents; **4.3×** vs monolithic on zero-days (arXiv:2406.01637) |
| [westonbrown/Cyber-AutoAgent](https://github.com/westonbrown/Cyber-AutoAgent) | Archived; claimed 85% XBOW. Historical |
| [straylabs-ai/deadend-cli](https://github.com/straylabs-ai/deadend-cli) | XBOW black-box 81% at ~$122 API cost |
| [ASCIT31/Dark-Moon](https://github.com/ASCIT31/Dark-Moon) | Web / cloud / AD / K8s; 50+ tools |
| [verialabs/ctf-agent](https://github.com/verialabs/ctf-agent) | 789★ MIT. Coordinator LLM (Claude or Codex) + per-challenge solver swarms racing models in isolated Docker (pwntools, radare2, GDB, SageMath). README: 52/52, 1st at BSidesSF 2026 |
| [chainreactors/tinyctfer](https://github.com/chainreactors/tinyctfer) | TCH S1 4th: ~100 lines, “intent is all you need” |
| [m-sec-org/BreachWeave](https://github.com/m-sec-org/BreachWeave) | TCH S2 1st: Manager / Solver / Observer; RTK rewrite for context corruption; Ralph-loop termination; 7-model race |
| [agnusdei1207/pentesting-public](https://github.com/agnusdei1207/pentesting-public) | Closed-core agent with public XBOW write-up (82.7% on fair attempts, MiniMax-M3, $0) |
| [Vasco0x4/AIDA](https://github.com/Vasco0x4/AIDA) | Isolated container, persistent assessment state |
| [yohannesgk/blacksmith](https://github.com/yohannesgk/blacksmith) | Docker image with standard tooling, web UI + CLI |
| [JoasASantos/NeuroSploit](https://github.com/JoasASantos/NeuroSploit) | Rust; specialist agents selected by surface; cross-model validation |
| [timsonner/autonomous-pentest-agent](https://github.com/timsonner/autonomous-pentest-agent) | Ralph Wiggum loop + Kali-in-Docker via MCP + Copilot CLI |
| [mvdevnull/pentest-claude](https://github.com/mvdevnull/pentest-claude) | Kali Rolling image with Claude Code + pentest-ai-agents preloaded |

---

## 4. Code-security / agentic SAST harnesses

This is the other half of the field, and the closer analog to a white-box codesec-style pipeline (recon → hunt → validate → dedupe → trace → feedback → report).

### 4.1 Reference pipelines from labs that actually run them

**[anthropics/defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness)** — ~6.9–7.4k stars depending on snapshot, Apache-2.0.  
Open-source reference from Anthropic’s Project Glasswing / Mythos work. Interactive Claude Code skills (`/threat-model`, `/vuln-scan`, `/triage`, `/patch`) plus an autonomous `harness/` pipeline (recon → find → verify → report → patch) aimed at C/C++ memory bugs with Docker + ASAN. **Constraints are in code, not prompts:** every agent in a gVisor container, egress allowlisted to the API via a CONNECT proxy. Fresh container per stage; only PoC bytes cross the boundary into report. Repo is explicitly a reference, not a product (and marked unmaintained; product is Claude Security).  
**Steal:** sandbox-as-policy, second-agent adversarial triage, severity from *precondition count*, “fixing A fixes B” as the duplicate definition.

**[google/mantis](https://github.com/google/mantis)** — ~576–947 stars (early; growing), Apache-2.0, skills not a binary.  
16 named skills a coding agent executes in order: VCS history → semantic index → threat model → hypotheses → research → dedupe → review → reproduce (gVisor) → patch. Stack-agnostic; Google used it with Gemini CLI / Antigravity. Shannon 3.0’s code-analysis pipeline is an adaptation of this. Install: `npx skills add google/mantis`.  
**Steal:** skills as the unit of methodology; explicit false-positive filter; reproducers sandboxed.

**[visa/visa-vulnerability-agentic-harness](https://github.com/visa/visa-vulnerability-agentic-harness)** (VVAH) — ~1.8k stars, Apache-2.0.  
Four-phase S0–S11 pipeline (static seed → detection/reporting → optional remediate/validate), built on Glasswing learnings. **Default profile does not compile, execute, or grant Bash**; optional S6 exploit verification sends live HTTP only to localhost. Every role can point at its own model/provider. Emits Markdown + SARIF. Profiles: `default.yaml` / `full.yaml` (model-derived seed) and `taint.yaml` (operator-supplied source/sink).  
**Steal:** per-role model split, SARIF as the interchange format, taint profile as an optional deterministic seed, conservative default tool policy.

**[evilsocket/audit](https://github.com/evilsocket/audit)** — ~855 stars, MIT.  
From-scratch reimplementation of Cloudflare Glasswing’s 8 stages on the Claude Code Agent SDK (subscription OAuth, no API key). Stages: Recon (Opus) → Hunt (Sonnet, one attack class per agent) → Validate (Opus, *tries to disprove*) → Gapfill → Dedupe → Trace (reachability) → Feedback → Report. Deliberate model disagreement + explicit reachability gate. This is the closest public cousin to codesec’s stage graph. **Caveat:** Hunt agents have Bash and are **not OS-sandboxed** — same hole codesec currently has.

**[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)** — ~2.7–3.3k stars.  
The single-repo skill that seeded Cloudflare’s fleet harness. Parallel hunting agents, separate disprove agents, schema-validated `findings.json`, independent record verification. Cloudflare’s follow-up posts are required reading:

- [Project Glasswing, What Mythos Showed Us](https://blog.cloudflare.com/cyber-frontier-models/) — four lessons: tight scope, deliberate disagreement, “is it buggy?” ≠ “can an attacker reach it?”, fan-out then dedupe. A single session covers ~0.1% of a 100k-line repo before compaction discards findings.
- [Build Your Own Vulnerability Harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness/) — SQLite externalized state, each agent <25% of context, hunter ≠ judge, dedicated dedupe agents. 20,799 raw → 12,057 survived validation → 5,442 folded as duplicates. One skill run finds ~half the bugs of repeated runs.

**[openai/codex-security](https://github.com/openai/codex-security)** — ~10.7k stars, Apache-2.0.  
CLI + TypeScript SDK (`@openai/codex-security`) for policy, find, validate, fix. OpenAI’s “Defense Factory” numbers (vendor): 37% of findings deduplicated, 0.81% FP after runtime validation, 100% Codex-generated patches, 0.53% rolled back. Complementary reading: [openai.com/the-defense-factory](https://openai.com/the-defense-factory/).

### 4.2 Other code-audit harnesses

| Repo | Stars (approx) | Notes |
|---|---|---|
| [vercel-labs/deepsec](https://github.com/vercel-labs/deepsec) | 6.4k | Coding-agent security harness for large codebases. One of the three star-leaders in the SAST-harness class |
| [trailofbits/skills](https://github.com/trailofbits/skills) | 6.3k | Distilled from ToB audit practice |
| [gadievron/raptor](https://github.com/gadievron/raptor) | 3.4k | Static + binary + validation + exploit gen + patch. Semgrep/CodeQL plus Linux namespaces, Landlock, seccomp |
| [capitalone/VulnHunter](https://github.com/capitalone/VulnHunter) | 794 | Attacker-first analysis on source. Verifier is **read-only** (no Bash, no network); generates PoCs from code |
| [openhackai/OpenHack](https://github.com/openhackai/OpenHack) | — | Recon / specialist hunts / independent validation; **open-weight models only**. Optional Docker + headless browser to exploit-test findings. Help Net Security attributes it to Hadrian; README does not confirm |
| [securelayer7/sandyaa](https://github.com/securelayer7/sandyaa) | — | Claude Code CLI piggyback. Drops findings not reachable from untrusted input. Advertised CVE counts not independently verified |
| [Lazarus-AI/clearwing](https://github.com/Lazarus-AI/clearwing) | — | Rank files, specialist fan-out, sanitizer crashes as ground truth; separate network-pentest mode |
| [ZealynxSecurity/krait](https://github.com/ZealynxSecurity/krait) | — | Solidity / Claude Code; 101 heuristics, 8 kill gates that try to disprove every finding; 100% precision on 50 Code4rena contests (v8 baseline, vendor) |
| [Kritt-ai/open-kritt](https://github.com/Kritt-ai/open-kritt) | — | Self-hosted orchestrator; bug-bounty payouts credited to a Blockian identity |
| [GitHubSecurityLab/seclab-taskflow-agent](https://github.com/GitHubSecurityLab/seclab-taskflow-agent) | — | YAML-driven multi-agent + CodeQL |
| [ucsb-mlsec/VulnLLM-R](https://github.com/ucsb-mlsec/VulnLLM-R) | — | 7B vuln-reasoning model; claimed to beat CodeQL / AFL++ / Claude-3.7 on several languages (arXiv:2512.07533) |
| Cisco `ai-deep-sast` | 39 | Early; listed in AppSec Santa’s nine-harness tally (~29k stars combined, no OSS market leader declared) |

Google Chrome’s internal pipeline is not a public harness but is a results datapoint: agents across discovery/triage/fix/release, **1,072 security bugs** in two milestones, including a 13-year-old sandbox escape ([blog](https://blog.google/security/chrome-stronger-with-every-update/)). Ramp ([100 vulns patched with 0 humans](https://engineering.ramp.com/post/100-vulnerabilities-patched-with-0-humans)) and Shopify River are the two best public *remediation*-loop write-ups; manager agents rejected 40% of proposals that humans confirmed were FPs.

---

## 5. Tsecbench and Tencent hackathon teams

This is the cluster most relevant to codesec: hosted, time-boxed, multi-category (web / binary / exploit / pentest / cloud / evasion), token-and-wall-clock accounted. Existing in-repo analysis: [`docs/tsecbench-team-repos-analysis.md`](tsecbench-team-repos-analysis.md).

### 5.1 Tsecbench v1 official board (hosted runs, 2026-09-11 snapshot)

Source: [tsecbench.zc.tencent.com](https://tsecbench.zc.tencent.com/).

| Rank | Agent | Score | Open repo (if any) |
|---|---|---|---|
| 1 | Cairn_Y (leixiao) | 97.14 | [oritera/Cairn](https://github.com/oritera/Cairn) |
| 2 | Miko (Kunluns) | 95.19 | — |
| 3 | Hiveptagi | 93.91 | — (PentAGI-family naming) |
| 4 | CyberPenda | 93.82 | [n1majne3/CyberPenda](https://github.com/n1majne3/CyberPenda) |
| 5 | RiftX | 93.47 | [Ch1nfo/RiftX](https://github.com/Ch1nfo/RiftX) |
| 6 | 应龙安全引擎 V1.1 | 92.00 | — |
| 7 | 0xSPY | 91.90 | — |
| 8 | Bean | 91.75 | — |
| 9 | Pentest4DSH | 91.08 | — |
| 10 | 虫洞 | 91.03 | — |
| 12 | ATX | (on board) | [Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX) |

**[Yean-Sec/StrikeAgent_AtkBrain-Flash](https://github.com/Yean-Sec/StrikeAgent_AtkBrain-Flash)** is the other high-signal open Tsecbench-adjacent system (Cybench board + Tencent hosted runs). Open-sourced on X 2026-09-07 by @Southwin11, amplified by @thegrugq and @AabyssZG. Attack-graph self-loop on Claude Code SDK, supervisor only at round boundaries, cross-run memory of transferable tactics (when/do/avoid/chain, scrubbed of targets).

### 5.2 TCH season 2 (2026-04) — top open repos

From [Yeti-791/Tsec-Hackathon](https://github.com/Yeti-791/Tsec-Hackathon):

| Place | Team | Repo | Distinctive idea |
|---|---|---|---|
| 1 | ai小分队 | [m-sec-org/BreachWeave](https://github.com/m-sec-org/BreachWeave) | Manager / Solver / Observer. Observer is *bypass* supervision (does not interrupt). RTK three-layer rewrite against context corruption. Ralph-loop termination. 7 models race for the job |
| 3 | Bytex | [oritera/Cairn](https://github.com/oritera/Cairn) | Blackboard + ant colony + emergence. Equal workers, dynamic tasks. **Only full-AK.** ~¥7,692 cost. Explicitly rejects predefined role-play as “a projection of human limits” |
| 7 | For Future | [chainreactors/aide-for-pentest](https://github.com/chainreactors/aide-for-pentest) | Pure-NL FSM. “Less Than Nothing”: *zero* domain knowledge on purpose so the model can emerge. Coordinator / P2P / Craft org modes |
| 17–20 | various | LingXi, llmnor, cloudever, Threonine/hackathon-pentest | Lower-rank but open |

### 5.3 TCH season 1 (2025-11)

| Place | Team | Repo |
|---|---|---|
| 2 | xjtuHunter | [xjtuHunter](https://github.com/xjtuHunter) (scene-aware black-box) |
| 3 | BinX | [SanMuzZzZz/LuaN1aoAgent](https://github.com/SanMuzZzZz/LuaN1aoAgent) |
| 4 | Antix | [chainreactors/tinyctfer](https://github.com/chainreactors/tinyctfer) |
| 6 | NeuroSploit | [Neuro-Sploit](https://github.com/Neuro-Sploit) |
| 7 | ai小分队 | [m-sec-org/xbow-competition](https://github.com/m-sec-org/xbow-competition) |
| 8 | D@wnEdg3 | [TJR181/Cruiser_public](https://github.com/TJR181/Cruiser_public) |
| 9 | yhy | [yhy0/CHYing-agent](https://github.com/yhy0/CHYing-agent) |
| 10 | sickhack | [SickHackPark/SickHackShark](https://github.com/SickHackPark/SickHackShark) |
| 17 | 小白战队 | [Ed1s0nZ/CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI) |

Also in the codesec local list (`tsecbench_github_repos.txt`): [passer-W/ctfSolver](https://github.com/passer-W/ctfSolver), [ignite0522/round_table](https://github.com/ignite0522) (knights + Merlin scheduler + Arthur arbiter, FunSearch islands), [n1majne3/CyberPenda](https://github.com/n1majne3/CyberPenda) (Go control plane, blackboard v2, receipts, digest snapshots).

**Patterns the Tsecbench/TCH field independently converged on** (also documented in the in-repo analysis):

1. Cross-run memory of *methods*, never targets (StrikeAgent).
2. Digest-style shared state: titles always, bodies on demand; dead-ends always fully visible (round_table, CyberPenda).
3. Strategy knobs instead of personality prompts (round_table `KnightPolicy`).
4. Evidence-gated verification statuses; PoC presence ≠ confidence (StrikeAgent).
5. LLM failover pool + process-wide circuit breaker (ARTEX).
6. Supervisor only at round boundaries; stall/starvation detection (StrikeAgent, BreachWeave Observer).
7. Blackboard / pheromone / equal-worker designs beating hardcoded recon→scan→exploit roleplay (Cairn, Pentest-Swarm, CyberPenda).

---

## 6. DARPA AIxCC — cyber reasoning systems

Seven finalist CRS systems, built to **find and patch** vulns in real OSS (C/Java), released as competition snapshots. This is the binary / memory-safety cousin of the web-pentest agents.

| Place | Team | System | Repo |
|---|---|---|---|
| 1 | Team Atlanta | ATLANTIS | [Team-Atlanta/aixcc-afc-atlantis](https://github.com/Team-Atlanta/aixcc-afc-atlantis) (~642★) — symbolic + directed fuzz + LLM. Paper: [arXiv:2509.14589](https://arxiv.org/abs/2509.14589) |
| 2 | Trail of Bits | Buttercup | [trailofbits/buttercup](https://github.com/trailofbits/buttercup) (~1.7k★) — OSS-Fuzz campaign + multi-agent patcher |
| 3 | Theori | RoboDuck | [theori-io/aixcc-afc-archive](https://github.com/theori-io/aixcc-afc-archive) |
| 4 | All You Need Is A Fuzzing Brain | FuzzingBrain | [o2lab/afc-crs-all-you-need-is-a-fuzzing-brain](https://github.com/o2lab/afc-crs-all-you-need-is-a-fuzzing-brain) / [fuzzingbrain/…](https://github.com/fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain). Follow-up FuzzingBrain V2: 29 0-days, 2 CVEs ([arXiv:2605.21779](https://arxiv.org/abs/2605.21779)) |
| 5 | Shellphish | ARTIPHISHELL | [shellphish/artiphishell](https://github.com/shellphish/artiphishell) |
| 6 | 42-b3yond-6ug | BugBuster | [42-b3yond-6ug/42-b3yond-6ug-crs](https://github.com/42-b3yond-6ug/42-b3yond-6ug-crs) |
| 7 | Lacrosse (SIFT) | Lacrosse CRS | [siftech/afc-crs-lacrosse](https://github.com/siftech/afc-crs-lacrosse) |

Related fuzzing harnesses (not AIxCC snapshots): [google/oss-fuzz-gen](https://github.com/google/oss-fuzz-gen), [ChatAFLndss/ChatAFL](https://github.com/ChatAFLndss/ChatAFL), [fuzz4all/fuzz4all](https://github.com/fuzz4all/fuzz4all), [FuzzAnything/PromptFuzz](https://github.com/FuzzAnything/PromptFuzz), [vul337/FirmAgent](https://github.com/vul337/FirmAgent) (NDSS 2026 IoT).

---

## 7. Skills, MCP, sandboxes, general harnesses

These are the *components* a pentest/code-sec agent sits on. Several “agents” in §3 are thin wrappers around this layer.

### 7.1 General agent runtimes used as pentest substrates

| Repo | Stars | Role |
|---|---|---|
| [earendil-works/pi](https://github.com/earendil-works/pi) | 104k | Minimal open coding-agent harness. **Shannon 2.0’s runtime.** MIT |
| [anthropics/claude-code](https://github.com/anthropics/claude-code) | (product) | Default substrate for StrikeAgent, T3MP3ST, pentest-ai-agents, Mantis, Cloudflare skill, Anthropic defending-code |
| [openai/codex](https://github.com/openai/codex) | — | ARTEMIS spawns Codex instances as subagents |
| [strands-agents/harness-sdk](https://github.com/strands-agents/harness-sdk) | — | AWS-origin SDK: loop, budgets, MCP, multi-agent, evals. Not security-specific |

A 2026 Alias Robotics paper, *[Towards Cybersecurity Superintelligence: What’s the Best Harness for Cybersecurity?](https://arxiv.org/abs/2605.28334)*, ran five scaffolds on 33 challenges and found **no single harness wins**. A blackboard combining structurally diverse scaffolds hit 57.6% vs 45.5% for the best individual scaffold. That result is the theoretical backing for Cairn / CyberPenda / CSI-style combiners.

A counter-paper worth pairing with it: *[Baselines Before Architecture](https://arxiv.org/abs/2607.13085)* — same-model plain-agent baselines often eat the “harness gain.” Do not credit the scaffold until you have that ablation.

### 7.2 Skill packs

| Repo | Stars | What |
|---|---|---|
| [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | 32k | 817 skills, 29 domains, mapped to ATT&CK / NIST CSF / ATLAS / D3FEND / AI RMF / F3. **Not affiliated with Anthropic** |
| [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills) | 3.2k | CTF dispatcher across web/pwn/crypto/RE/forensics |
| [Eyadkelleh/awesome-skills-security](https://github.com/Eyadkelleh/awesome-skills-security) | 374 | SecLists packed as skills |
| [transilienceai/communitytools](https://github.com/transilienceai/communitytools) | 502 | 26 skills + 3 integrations; maintainers claim 104/104 on their own CTF bench |
| [Masriyan/Claude-Code-CyberSecurity-Skill](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill) | — | 19 skills, offense + defense + RE + SOC |

### 7.3 Offensive MCP servers

| Repo | Stars | What |
|---|---|---|
| [PortSwigger/mcp-server](https://github.com/portswigger/mcp-server) | 1.1k | Official Burp MCP |
| [Wh0am123/MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server) | 808 | In Kali apt: `mcp-kali-server` |
| [FuzzingLabs/mcp-security-hub](https://github.com/FuzzingLabs/mcp-security-hub) | 776 | 38 containerized MCP servers, 300+ tools |
| [GH05TCREW/MetasploitMCP](https://github.com/GH05TCREW/MetasploitMCP) | 722 | Metasploit via MCP |
| [MorDavid/BloodHound-MCP-AI](https://github.com/MorDavid/BloodHound-MCP-AI) | 375 | AD attack paths as NL |
| [w0h1v/mcp-shodan](https://github.com/w0h1v/mcp-shodan) | 161 | Shodan + CVEDB |
| [DMontgomery40/pentest-mcp](https://github.com/DMontgomery40/pentest-mcp) | 143 | nmap/hydra/sqlmap/nuclei/hashcat + SoW gate |
| [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) | — | IDA to agents |
| [mrphrazer/binary-ninja-headless-mcp](https://github.com/mrphrazer/binary-ninja-headless-mcp) | — | 180 BN tools |

### 7.4 Sandboxes (the actual security boundary)

| Repo | Role |
|---|---|
| [google/gvisor](https://github.com/google/gvisor) | Used by Anthropic defending-code and Mantis reproducers |
| [anthropic-experimental/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) | FS + network restrictions |
| [e2b-dev/E2B](https://github.com/e2b-dev/E2B) | Cloud microVMs for agent code |
| [firecracker-microvm/firecracker](https://github.com/firecracker-microvm/firecracker) | Hardware isolation primitive |
| [microsandbox/microsandbox](https://github.com/microsandbox/microsandbox) | Local-first microVMs |

Consensus from Anthropic, Cloudflare, and X commentary on pentest-harness: **scope and sandbox belong in code.** Prompt-level “only test in-scope hosts” is not a control.

---

## 8. Benchmarks and eval harnesses

If you are going to claim a number, run it here.

| Bench | Repo / URL | What it measures |
|---|---|---|
| **XBOW Validation** | [xbow-engineering/validation-benchmarks](https://github.com/xbow-engineering/validation-benchmarks); patched fork [0ca/xbow-validation-benchmarks-patched](https://github.com/0ca/xbow-validation-benchmarks-patched) | 104 Dockerized web vulns. De-facto public yardstick. **Require flag recovery, state BB/WB, publish traces** |
| **Tsecbench** | [tsecbench.zc.tencent.com](https://tsecbench.zc.tencent.com/) | Hosted, multi-category, anti-cheat. The Chinese SOTA board |
| **Cybench** | [andyzorigin/cybench](https://github.com/andyzorigin/cybench) | 40 professional CTF tasks (ICLR 2025 Oral) |
| **CVE-Bench** | [uiuc-kang-lab/cve-bench](https://github.com/uiuc-kang-lab/cve-bench) | 40 critical web CVEs. Paper: Cy-Agent 2.5% success@5 one-day (GPT-4o); hierarchical T-Agent up to **13% one-day / 10% zero-day**. Do not trust third-party 70%+ recaps that are not in the paper |
| **SEC-bench** | [SEC-bench/SEC-bench](https://github.com/SEC-bench/SEC-bench) | Real-world PoC gen + patching. Paper: SOTA ≤ **18.0% PoC**, **34.0% patch** ([arXiv:2506.11791](https://arxiv.org/abs/2506.11791)) |
| **SEC-bench Pro** | arXiv:2605.26548 | 344 long-horizon bugs (V8 103, SpiderMonkey 104, Linux 137). Best: Codex + GPT-5.5 **201/344 (58.4%)**; OpenCode GLM-5 13/344 |
| **BountyBench** | [arXiv:2505.15216](https://arxiv.org/abs/2505.15216) | Codex CLI o3-high: 12.5% Detect / 90% Patch. Custom Claude 3.7 Sonnet Thinking: 67.5% Exploit (≤3 attempts) |
| **CyberGym** | [sunblaze-ucb/cybergym](https://github.com/sunblaze-ucb/cybergym) | 1,507 instances / 188 OSS-Fuzz projects. Best non-thinking: OpenHands + Claude Sonnet 4 **17.9%**. GPT-5 high-reasoning 22.0% on a 300-instance subset. Paper spawned 34 0-days. Ignore 80–90% figures on vendor pages |
| **CyberGym-E2E** | arXiv:2606.04460 | 920 vulns, discover → PoC → patch |
| **ExploitGym** | arXiv:2605.11086 | 898 “vuln → working attack” (userland / V8 / kernel). Mythos Preview: 157 |
| **NYU CTF Bench** | [NYU-LLM-CTF/nyuctf_agents](https://github.com/NYU-LLM-CTF/nyuctf_agents) | D-CIPHER + baselines |
| **AutoPenBench** | [lucagioacchini/auto-pen-bench](https://github.com/lucagioacchini/auto-pen-bench) | 33 pentest tasks |
| **BoxPwnr** | [0ca/BoxPwnr](https://github.com/0ca/BoxPwnr) (~449★) | **Meta-harness:** swap solver (Claude Code, Codex, Cursor, Grok, HackSynth, …) across HTB / THM / PortSwigger / XBOW / Cybench / picoCTF / CyberGym / Argus. Traces: [0ca/BoxPwnr-Traces](https://github.com/0ca/BoxPwnr-Traces) |
| **Linux privesc** | [ipa-lab/benchmark-privesc-linux](https://github.com/ipa-lab/benchmark-privesc-linux) | hackingBuddyGPT ground truth |
| **EthiBench** | Ethiack (Strix vs PentAGI vs Claude Code) | Precision/recall on vuln-bank, paygoat, xben-090 |
| **HackWorld** | [GUI-Agent/HackWorld](https://github.com/GUI-Agent/HackWorld) | Computer-use agents vs web vulns |
| **AgentCyberRange** | [AgentCyberRange](https://github.com/AgentCyberRange) | 110 vulns × 8 enterprise ranges |
| **3CB** | [apartresearch/3cb](https://github.com/apartresearch/3cb) | Offensive-capability robustness |
| **Enclave AI Hacking Race** | [enclave.ai/hackingrace](https://enclave.ai/hackingrace) | Tiny (4 tasks) but live; DeepSeek V4.1 Flash 11/11 as of 2026-09-11 |
| **CVE-GENIE** | [BUseclab/cve-genie](https://github.com/BUseclab/cve-genie) | Reconstruct env from a CVE + verifiable exploit (428/841, $2.77 avg) |

Independent comparative write-ups worth reading before trusting any vendor number:

- AppSec Santa, *[AI Pentesting Agents 2026](https://appsecsanta.com/research/ai-pentesting-agents-2026)* — 39 tools, six architecture patterns, eight benches aggregated. Same author: *[9 Free AI Code Security Harnesses](https://appsecsanta.com/newsletter/2026-w31)* (July 2026).
- Ethiack, *[Evaluating Pentesting Agents for the Real-World](https://ethiack.com/info-hub/research/evaluating-pentesting-agents-part-1)* — protocol, not a ranking.
- RedAmon wiki, *[XBOW Validation Benchmark](https://github.com/samugit83/redamon/wiki/XBOW-Validation-Benchmark)* — the adult-in-the-room table of who published traces.
- Doyensec, *[Aikido vs XBOW](https://doyensec.com/resources/ComparingAIApplicationSecurityTestingPlatforms_Doyensec.pdf)* — Aikido-sponsored, two apps. Aikido 17/19 TP on Fider + 32/32 on Photoview; XBOW 24/25 TP on Fider (did not finish Photoview). Combined marketing recap 49 vs 31 TP. XBOW’s Fider run needed pauses/restarts and the agent deleted the test account.
- Cycode, *[agentic SAST benchmark](https://cycode.com/blog/agentic-code-scanning-sast-benchmark/)* — vendor: harness + open-weight models 6/6 development-set CVEs vs Claude Opus 4.8 open-ended 4/6; OWASP Benchmark Java v1.2 91.63% vs “popular commercial SAST” 72.02%. Endor Labs (same roundup): AI SAST 192 real vulns, 2.6× Claude Opus 4.7, 3.5× Codex GPT-5.5, 2.4× Semgrep OSS, ~60% fewer FPs than Semgrep OSS. Treat as vendor-authored.

---

## 9. What X/Twitter is actually talking about

Sample of high-signal posts from this research window (not exhaustive).

| Date | Who | What landed |
|---|---|---|
| 2026-08-28 | [@Dinosn](https://x.com/Dinosn/status/2093188887854157917) | `S1N6H/pentest-harness` — 1k likes, 1.3k bookmarks. The post that made “pentest harness” a search term |
| 2026-08-22–26 | various, incl. Yarchi / Surehand | Strix as the breakout: 51k→57k→60k stars, “working exploit is the unit of proof” |
| 2026-09-02–07 | [@KeygraphHQ](https://x.com/KeygraphHQ) | Shannon 3.0: source-map first, exploit to confirm, SARIF, 47k stars |
| 2026-09-03 | [@PythonHub](https://x.com/PythonHub/status/2095425383000650201) | `lordx64/pentestkit` 104/104 XBOW claim (unverified traces) |
| 2026-09-07 | [@Southwin11](https://x.com/thegrugq/status/2097188469823209475) RT’d by @thegrugq, @AabyssZG | StrikeAgent open-source, Tencent board #3 at the time |
| 2026-09-07 | [@bountywriteups](https://x.com/bountywriteups/status/2096826533675745733), [@MAXdeg0](https://x.com/MAXdeg0/status/2097586373922320747) | PentestCode (OpenCode hard-fork) |
| 2026-09-07 | [@ome_mishra](https://x.com/ome_mishra/status/2096933374158102974) | Hacker-Harness (scope gates + Caido + H1/Bugcrowd) |
| 2026-09-08 | [@gittrend_io](https://x.com/gittrend_io/status/2097192492202627476) | H-mmer/pentest-agents (48 skills × many IDEs) |
| 2025-12 / 2026-01 | [@0x0SojalSec](https://x.com/0x0SojalSec), [@AISecHub](https://x.com/AISecHub), [@Dinosn](https://x.com/Dinosn) | Recurring PentestAgent / HexStrike shares — the 2025 “give the LLM Kali” wave |
| 2026-03-19 | [@ProulxKerem](https://x.com/ProulxKerem/status/2034632986474480053) | Proprietary Apex agent open-sourced with internal 60-app bench (video, 1.9M views) |

The X consensus, compressed:

1. **Proof-gated findings** (working exploit, second-agent re-run) are the quality bar. Scanner-style recall is unfashionable.
2. **Self-hosted + BYOK** is the privacy/authorization story people retweet.
3. **Skills-on-Claude-Code** is how methodology ships now, faster than writing a new Python agent.
4. **Tsecbench open-sourcing** (StrikeAgent, Cairn, CyberPenda, ARTEX) is the 2026 Chinese-community event; English Twitter mostly notices when @thegrugq RTs it.

---

## 10. Architecture patterns that keep showing up

Synthesized across the repos, papers, and X threads. Ordered by how often independent teams rediscovered them.

1. **Hunter ≠ judge.** Different model, different session, adversarial “disprove” prompt. Cloudflare, Anthropic, evilsocket/audit, Visa, pwnkit’s blind re-exploit, codesec’s validate panel.
2. **Reachability is a separate gate from “looks buggy.”** Trace / taint / ASAN crash / live PoC. Glasswing lesson #3; StrikeAgent `verified` vs `pending`.
3. **Externalize state.** SQLite / blackboard / attack graph / JSONL. Compaction will otherwise delete findings. Cloudflare, CyberPenda, Cairn, RedAmon (Neo4j), StrikeAgent graph.
4. **Digests, not dumps.** Titles + status always; bodies on demand; failed hypotheses always in the digest so they are not rediscovered (round_table, CyberPenda ADR-0004).
5. **Short-lived specialists, long-lived supervisor.** XBOW’s public architecture post; ARTEMIS; StrikeAgent “supervisor only at round boundaries”; BreachWeave Observer-as-bypass.
6. **Proof as the schema.** Replayable capsules (pentest-ai), SARIF (Shannon, VVAH, Strix CI), receipts (CyberPenda), canaries (pwnkit).
7. **Scope and sandbox in code.** gVisor + egress proxy (Anthropic), Docker-in-Docker Kali (several), owner-only credential store (pentest-harness).
8. **Cross-run memory of tactics, scrubbed of targets.** StrikeAgent `when/do/avoid/chain`. Almost nobody else does this well.
9. **Strategy diversity > roleplay diversity.** KnightPolicy knobs; 7-model race (BreachWeave); equal workers (Cairn). “Five reskinned LLMs” is a known failure mode in TCH write-ups.
10. **Harness ablation against a plain coding agent.** 2026 papers keep finding that Claude Code / Codex with a good prompt is a brutally strong baseline (arXiv:2605.21497, arXiv:2607.13085). If your scaffold cannot beat that, it is costume.

---

## 11. Closed / commercial (so the map is not lying by omission)

Not GitHub-first, but they set the capability ceiling the open harnesses are chasing.

| Product | What is public | Why it matters |
|---|---|---|
| **XBOW** | Closed platform. Founder Oege de Moor (Semmle / GitHub Copilot). ~$273M raised by late 2025, Series C 2026 >$1B valuation. #1 HackerOne US, 1,060+ valid reports. Pentest On-Demand from ~$4k. Open artifact: the 104 validation benchmarks | The commercial north star for *web* autonomy. Own agent ~85/104 on its own bench |
| **Anthropic Mythos / Claude Security** | Mythos Preview (Apr 2026) found thousands of high-sev issues in major OS/browsers; judged too capable for broad release. Glasswing partnerships with Cloudflare et al. Product: Claude Security. Open artifact: defending-code-reference-harness | The commercial north star for *code* autonomy |
| **Horizon3.ai NodeZero** | Autonomous network / AD / cloud. FedRAMP, NSA CAPT. Strongest public infra story |
| **Pentera** | Adversarial exposure validation, >$100M ARR, $1B+ valuation | Enterprise AEV, not an LLM-agent demo |
| **Aikido** | AppSec platform with an agentic scanner. Doyensec two-app comparison vs XBOW (Aikido-sponsored): more TPs overall, XBOW more precise on Fider but slower/less stable | Independent-ish (still sponsored) commercial bake-off |
| **Cycode, Endor Labs** | Agentic SAST vendors claiming harnessed scanners beat both unharnessed frontier coding agents and traditional SAST on their corpora | Useful as a *hypothesis* (harness > naked model); numbers are vendor |
| **MindFort, RunSybil, Hacktron, Borg, Escape, Penligent, Armadin** | Various AXR / black-box / repo-aware AppSec agents | Fast-moving 2026 vendor set; treat blogs as marketing |
| **Google Big Sleep / Project Naptime** | First widely reported AI-discovered production 0-day (SQLite) that OSS-Fuzz had missed | Existence proof for vuln-discovery agents outside CTF |
| **Alias CSI** | Closed combiner over Claude Code, Codex, CAI, Mistral, GCAI + alias* models. Claims Cybench 85% (alias3) and 2.6× on A&D CTFs | The “best harness is several harnesses” productization of CAI |

---

## 12. Papers that change how you build (short list)

Full 116-paper table: [Yeti-791/Awesome-Offensive-AI-Agentic-Landscape](https://github.com/Yeti-791/Awesome-Offensive-AI-Agentic-Landscape). The ones that should actually affect a harness design:

| Paper | Why |
|---|---|
| Deng et al., *PentestGPT*, USENIX Sec 2024, [arXiv:2308.06782](https://arxiv.org/abs/2308.06782) | Origin |
| Fang et al., *LLM Agents can Autonomously Exploit One-day Vulnerabilities*, [arXiv:2404.08144](https://arxiv.org/abs/2404.08144) | 87% with description, 7% without — the description-gap |
| Zhu et al., *Teams of LLM Agents can Exploit Zero-Day Vulnerabilities* (HPTSA), [arXiv:2406.01637](https://arxiv.org/abs/2406.01637) | 4.3× for hierarchical teams |
| Zhang et al., *Cybench*, ICLR 2025, [arXiv:2408.08926](https://arxiv.org/abs/2408.08926) | Standard CTF bench |
| Mayoral-Vilches et al., *CAI*, [arXiv:2504.06017](https://arxiv.org/abs/2504.06017) | Autonomy-level taxonomy |
| Lin et al., *ARTEMIS vs humans*, ICLR 2026, [arXiv:2512.09882](https://arxiv.org/abs/2512.09882) | Beat 9/10 professionals on a real 8k-host net |
| Alias, *Best Harness for Cybersecurity?*, [arXiv:2605.28334](https://arxiv.org/abs/2605.28334) | Blackboard-of-scaffolds > any single scaffold |
| Dhakal et al., *Baselines Before Architecture*, [arXiv:2607.13085](https://arxiv.org/abs/2607.13085) | Plain coding-agent ablation |
| He et al., *Agents4Pentest survey*, [arXiv:2607.02605](https://arxiv.org/abs/2607.02605) | 81-paper taxonomy, 2026 |
| Peng et al., *Hackers or Hallucinators?*, [arXiv:2604.05719](https://arxiv.org/abs/2604.05719) | 13 frameworks, >10B tokens, SoK |
| David & Gervais, *Towards Optimal Agentic Architectures*, [arXiv:2604.18718](https://arxiv.org/abs/2604.18718) | 600-run ablation, white-box vs black-box, web vs binary |

---

## 13. Suggested short-list to clone and actually read

If the goal is to steal harness ideas (not to collect stars):

**Must-read source (code-audit lineage — closest to codesec)**

1. [evilsocket/audit](https://github.com/evilsocket/audit) — 8-stage Glasswing clone, small enough to finish
2. [anthropics/defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness) — sandbox, triage rules, stage isolation
3. [google/mantis](https://github.com/google/mantis) — skill-shaped methodology
4. [visa/visa-vulnerability-agentic-harness](https://github.com/visa/visa-vulnerability-agentic-harness) — S0–S11 + SARIF
5. [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) + the two Cloudflare posts

**Must-read source (pentest lineage — Tsecbench-grade)**

6. [n1majne3/CyberPenda](https://github.com/n1majne3/CyberPenda)
7. [Yean-Sec/StrikeAgent_AtkBrain-Flash](https://github.com/Yean-Sec/StrikeAgent_AtkBrain-Flash)
8. [Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX)
9. [oritera/Cairn](https://github.com/oritera/Cairn)
10. [m-sec-org/BreachWeave](https://github.com/m-sec-org/BreachWeave)
11. [ignite0522](https://github.com/ignite0522) (round_table)

**Must-read source (public product-grade)**

12. [usestrix/strix](https://github.com/usestrix/strix)
13. [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon) (and [earendil-works/pi](https://github.com/earendil-works/pi) as its runtime)
14. [samugit83/redamon](https://github.com/samugit83/redamon) (best published XBOW traces)
15. [Stanford-Trinity/ARTEMIS](https://github.com/Stanford-Trinity/ARTEMIS)
16. [0ca/BoxPwnr](https://github.com/0ca/BoxPwnr) (eval harness, not a pentester)

In-repo companion: [`docs/tsecbench-team-repos-analysis.md`](tsecbench-team-repos-analysis.md) already extracts transferable tactics from ARTEX, StrikeAgent, CyberPenda, and round_table.

---

## 14. Full repo catalog (quick lookup)

Grouped, not ranked. Stars omitted when the snapshot was noisy.

### Indexes
- https://github.com/Ed-Marcavage/awesome-security-agent-harnesses
- https://github.com/Yeti-791/Awesome-Offensive-AI-Agentic-Landscape
- https://github.com/Yeti-791/Tsec-Hackathon
- https://github.com/scadastrangelove/awesome-ai-security-tools
- https://github.com/EvanThomasLuke/Awesome-AI-Hacking-Agents
- https://github.com/fr0gger/Awesome-GPT-Agents
- https://github.com/raphabot/awesome-cybersecurity-agentic-ai
- https://github.com/simon-p-j-r/LLM4Pentest
- https://github.com/gmh5225/awesome-ai-security
- https://github.com/jiep/offensive-ai-compilation

### Pentest / red-team agents
- https://github.com/usestrix/strix
- https://github.com/KeygraphHQ/shannon
- https://github.com/vxcontrol/pentagi
- https://github.com/GreyDGL/PentestGPT
- https://github.com/0x4m4/hexstrike-ai
- https://github.com/aliasrobotics/cai
- https://github.com/Ed1s0nZ/CyberStrikeAI
- https://github.com/elder-plinius/T3MP3ST
- https://github.com/GH05TCREW/pentestagent
- https://github.com/oritera/Cairn
- https://github.com/samugit83/redamon
- https://github.com/Armur-Ai/Pentest-Swarm-AI
- https://github.com/0xSteph/pentest-ai
- https://github.com/0xSteph/pentest-ai-agents
- https://github.com/SanMuzZzZz/LuaN1aoAgent
- https://github.com/PentesterFlow/agent
- https://github.com/ipa-lab/hackingBuddyGPT
- https://github.com/PwnKit-Labs/pwnkit
- https://github.com/Stanford-Trinity/ARTEMIS
- https://github.com/S1N6H/pentest-harness
- https://github.com/N0tMilk/prometheus-pentest-harness
- https://github.com/omemishra/Hacker-Harness
- https://github.com/wudidike/pentest_skill
- https://github.com/H-mmer/pentest-agents
- https://github.com/s0ld13rr/pentestcode
- https://github.com/lordx64/pentestkit
- https://github.com/stuxlabs/AWE
- https://github.com/arthurgervais/mapta
- https://github.com/KHenryAegis/VulnBot
- https://github.com/andreashappe/cochise
- https://github.com/uiuc-kang-lab/HPTSA
- https://github.com/westonbrown/Cyber-AutoAgent
- https://github.com/straylabs-ai/deadend-cli
- https://github.com/ASCIT31/Dark-Moon
- https://github.com/verialabs/ctf-agent
- https://github.com/chainreactors/tinyctfer
- https://github.com/chainreactors/aide-for-pentest
- https://github.com/m-sec-org/BreachWeave
- https://github.com/m-sec-org/xbow-competition
- https://github.com/n1majne3/CyberPenda
- https://github.com/Autumn-27/ARTEX
- https://github.com/Yean-Sec/StrikeAgent_AtkBrain-Flash
- https://github.com/Ch1nfo/RiftX
- https://github.com/yhy0/CHYing-agent
- https://github.com/TJR181/Cruiser_public
- https://github.com/SickHackPark/SickHackShark
- https://github.com/passer-W/ctfSolver
- https://github.com/Vasco0x4/AIDA
- https://github.com/yohannesgk/blacksmith
- https://github.com/JoasASantos/NeuroSploit
- https://github.com/berylliumsec/nebula
- https://github.com/bugbasesecurity/pentest-copilot
- https://github.com/zakirkun/guardian-cli
- https://github.com/Gowtham-Darkseid/AutoPentestX
- https://github.com/xalgord/xalgorix
- https://github.com/ARCANGEL0/EVA
- https://github.com/SHAdd0WTAka/Zen-Ai-Pentest
- https://github.com/aielte-research/HackSynth
- https://github.com/CyberStrikeus/CyberStrike
- https://github.com/BugTraceAI/BugTraceAI
- https://github.com/timsonner/autonomous-pentest-agent
- https://github.com/mvdevnull/pentest-claude
- https://github.com/hardenedlinux/agentic-ai-pentest
- https://github.com/OWASP/Nettacker

### Code-audit / agentic SAST
- https://github.com/anthropics/defending-code-reference-harness
- https://github.com/google/mantis
- https://github.com/visa/visa-vulnerability-agentic-harness
- https://github.com/evilsocket/audit
- https://github.com/cloudflare/security-audit-skill
- https://github.com/openai/codex-security
- https://github.com/capitalone/VulnHunter
- https://github.com/Lazarus-AI/clearwing
- https://github.com/ZealynxSecurity/krait
- https://github.com/Kritt-ai/open-kritt
- https://github.com/openhackai/OpenHack
- https://github.com/gadievron/raptor
- https://github.com/trailofbits/skills
- https://github.com/vercel-labs/deepsec
- https://github.com/GitHubSecurityLab/seclab-taskflow-agent
- https://github.com/ucsb-mlsec/VulnLLM-R
- https://github.com/securelayer7/sandyaa

### AIxCC CRS + fuzzing
- https://github.com/Team-Atlanta/aixcc-afc-atlantis
- https://github.com/trailofbits/buttercup
- https://github.com/theori-io/aixcc-afc-archive
- https://github.com/o2lab/afc-crs-all-you-need-is-a-fuzzing-brain
- https://github.com/shellphish/artiphishell
- https://github.com/42-b3yond-6ug/42-b3yond-6ug-crs
- https://github.com/siftech/afc-crs-lacrosse
- https://github.com/google/oss-fuzz-gen
- https://github.com/ChatAFLndss/ChatAFL
- https://github.com/fuzz4all/fuzz4all
- https://github.com/FuzzAnything/PromptFuzz
- https://github.com/vul337/FirmAgent

### Evals
- https://github.com/0ca/BoxPwnr
- https://github.com/0ca/BoxPwnr-Traces
- https://github.com/0ca/xbow-validation-benchmarks-patched
- https://github.com/andyzorigin/cybench
- https://github.com/uiuc-kang-lab/cve-bench
- https://github.com/SEC-bench/SEC-bench
- https://github.com/sunblaze-ucb/cybergym
- https://github.com/NYU-LLM-CTF/nyuctf_agents
- https://github.com/lucagioacchini/auto-pen-bench
- https://github.com/ipa-lab/benchmark-privesc-linux
- https://github.com/BUseclab/cve-genie
- https://github.com/apartresearch/3cb
- https://github.com/GUI-Agent/HackWorld

### Skills / MCP / sandboxes / runtimes
- https://github.com/earendil-works/pi
- https://github.com/mukul975/Anthropic-Cybersecurity-Skills
- https://github.com/ljagiello/ctf-skills
- https://github.com/Eyadkelleh/awesome-skills-security
- https://github.com/transilienceai/communitytools
- https://github.com/portswigger/mcp-server
- https://github.com/Wh0am123/MCP-Kali-Server
- https://github.com/FuzzingLabs/mcp-security-hub
- https://github.com/GH05TCREW/MetasploitMCP
- https://github.com/MorDavid/BloodHound-MCP-AI
- https://github.com/google/gvisor
- https://github.com/anthropic-experimental/sandbox-runtime
- https://github.com/e2b-dev/E2B
- https://github.com/strands-agents/harness-sdk

---

## 15. Sources

**Indexes and catalogs**
- https://github.com/Ed-Marcavage/awesome-security-agent-harnesses
- https://github.com/Yeti-791/Awesome-Offensive-AI-Agentic-Landscape (snapshot 2026-09-11)
- https://github.com/Yeti-791/Tsec-Hackathon
- https://tsecbench.zc.tencent.com/ (leaderboard snapshot 2026-09-11)

**Project pages (sampled)**
- https://github.com/usestrix/strix — https://www.strix.ai/open-source-pentesting
- https://github.com/KeygraphHQ/shannon — https://keygraph.io/open-source — discussions #405 (2.0), #439 (3.0)
- https://github.com/anthropics/defending-code-reference-harness
- https://github.com/google/mantis
- https://github.com/visa/visa-vulnerability-agentic-harness
- https://github.com/evilsocket/audit
- https://github.com/openai/codex-security
- https://github.com/PwnKit-Labs/pwnkit — https://pwnkit.com/
- https://github.com/Stanford-Trinity/ARTEMIS
- https://github.com/0ca/BoxPwnr
- https://github.com/aliasrobotics/cai — https://aliasrobotics.com/cai.php
- https://github.com/earendil-works/pi

**Eval and survey writing**
- https://appsecsanta.com/research/ai-pentesting-agents-2026
- https://ethiack.com/info-hub/research/evaluating-pentesting-agents-part-1
- https://github.com/samugit83/redamon/wiki/XBOW-Validation-Benchmark
- https://doyensec.com/resources/ComparingAIApplicationSecurityTestingPlatforms_Doyensec.pdf
- https://cycode.com/blog/agentic-code-scanning-sast-benchmark/
- https://appsecsanta.com/newsletter/2026-w31
- https://arxiv.org/abs/2506.11791 (SEC-bench)
- https://arxiv.org/abs/2605.26548 (SEC-bench Pro)
- https://arxiv.org/abs/2505.15216 (BountyBench)
- https://blog.cloudflare.com/cyber-frontier-models/
- https://blog.cloudflare.com/build-your-own-vulnerability-harness/
- https://openai.com/the-defense-factory/
- https://engineering.ramp.com/post/100-vulnerabilities-patched-with-0-humans
- https://shopify.engineering/river-vulnerability-remediation
- https://blog.google/security/chrome-stronger-with-every-update/

**X/Twitter (conversation IDs in §9)**
- @Dinosn 2093188887854157917 (pentest-harness)
- @Southwin11 via @thegrugq 2097188469823209475 (StrikeAgent)
- @KeygraphHQ 2095258276640538971 (Shannon)
- @PythonHub 2095425383000650201 (pentestkit)
- @MAXdeg0 2097586373922320747 (PentestCode)

**In-repo**
- `docs/tsecbench-team-repos-analysis.md`
- `tsecbench_github_repos.txt`

---

*This report is a literature and repo survey, not an endorsement, and not authorization to test anything. Several listed tools wrap real exploit frameworks. Star counts and leaderboard rows will be stale within weeks.*
