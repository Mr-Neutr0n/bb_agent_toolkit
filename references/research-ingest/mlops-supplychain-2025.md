# MLOps + AI Supply Chain Security — 2025/2026 Research Ingest

Cluster: `mlops-supplychain` · Ingested: 2026-08-15 · Audit date: 2026-08-15 (research-freshness audit pass).
Freshness window (operator rule): CURRENT = published 2026-06-01 or later; RECENT = 2026-01-01..2026-05-31; OUTDATED = 2025 or earlier (legacy context only, never treated as current technique). Original ingest split ("8/8 fresh") is superseded by the tier table below.

## FRESHNESS-TIER (audited 2026-08-15)

| # | Source | Pub date (verified) | Tier |
|---|---|---|---|
| 1 | nullifAI Hugging Face Pickle Attack Analysis (Safeguard.sh) | 2025-02-10 | OUTDATED |
| 2 | Malicious attack method on hosted ML models now targets PyPI (ReversingLabs) | 2025-05-23 | OUTDATED |
| 3 | Malicious packages deepseeek and deepseekai (PT ESC) | 2025-02-03 | OUTDATED |
| 4 | CVE-2025-11201: MLflow RCE (SentinelOne) | 2025-10-29 | OUTDATED |
| 5 | CVE-2025-15379: MLflow command injection RCE (SentinelOne) | 2026-04-02 ✓ | RECENT |
| 6 | LLaVA-NeXT HuggingFace Token Disclosure (Tenable TRA-2025-16) | 2025-06-10 | OUTDATED |
| 7 | ConfigScan — A Rusty Link in the AI Supply Chain (arXiv:2505.01067) | 2025-05-02 | OUTDATED |
| 8 | COLLAPOIS — collaborative backdoor poisoning (arXiv:2504.12875) | 2025-04-25 | OUTDATED |
| S1 | PyPI Malicious Packages 2025 Report (Safeguard.sh) | 2025-03-28 | OUTDATED |
| S2 | MalHug: "Models Are Codes" (ASE'24) | 2024-10 | OUTDATED |
| S3 | Typo Squatting Threats in HF Ecosystem (Internetware) | 2025-07 | OUTDATED |
| S4 | PickleBall (CCS'25) | 2025 | OUTDATED |
| S5 | FeRA federated backdoor defense (arXiv:2505.10297) | 2025-05 | OUTDATED |
| S6 | GHSA-wf7f-8fxf-xfxc — MLflow PyTorch flavor pickle RCE | 2025 | OUTDATED |
| S7 | MLflow #21083 — pyfunc weights_only not propagated | 2026-02-23 ✓ (created; upd. 2026-02-25) | RECENT |

Totals: CURRENT 0 · RECENT 2 · OUTDATED 13. Dates verified at audit for the two RECENT movers (SentinelOne page published 2026-04-02; mlflow issue #21083 created 2026-02-23 — file previously said 2026-02-24, corrected). **Cluster gap**: no 2026-06+ source at all — ML supply-chain coverage for the CURRENT window must come from fresh ingest (fresh-2026-agent-mcp.md / fresh-2026-huntr.md adjacent clusters); treat every technique below as legacy-baseline pending 2026 re-verification.

## SOURCES

| # | URL | Title | Pub date | Tier |
|---|---|---|---|---|
| 1 | https://safeguard.sh/resources/blog/nullifai-broken-pickles-huggingface-attack | nullifAI Hugging Face Pickle Attack Analysis (Aisha Rahman / Safeguard.sh, on ReversingLabs disclosure) | 2025-02-10 | OUTDATED |
| 2 | https://www.reversinglabs.com/blog/malicious-attack-method-on-hosted-ml-models-now-targets-pypi | Malicious attack method on hosted ML models now targets PyPI (Karlo Zanki, ReversingLabs) | 2025-05-23 | OUTDATED |
| 3 | https://global.ptsecurity.com/en/research/pt-esc-threat-intelligence/malicious-packages-deepseeek-and-deepseekai-published-in-python-package-index/ | Malicious packages deepseeek and deepseekai published in Python Package Index (PT ESC) | 2025-02-03 | OUTDATED |
| 4 | https://www.sentinelone.com/vulnerability-database/cve-2025-11201/ | CVE-2025-11201: LFProjects MLflow RCE Vulnerability (SentinelOne vuln db) | 2025-10-29 | OUTDATED |
| 5 | https://www.sentinelone.com/vulnerability-database/cve-2025-15379/ | CVE-2025-15379: MLflow Command Injection RCE Vulnerability (SentinelOne vuln db) | 2026-04-02 ✓ | RECENT |
| 6 | https://www.tenable.com/security/research/tra-2025-16 | LLaVA-NeXT HuggingFace Token Disclosure (Tenable Research Advisory TRA-2025-16) | 2025-06-10 | OUTDATED |
| 7 | https://arxiv.org/html/2505.01067v1 | A Rusty Link in the AI Supply Chain: Detecting Evil Configurations on Hugging Face — ConfigScan | 2025-05-02 | OUTDATED |
| 8 | https://arxiv.org/html/2504.12875 | A Client-level Assessment of Collaborative Backdoor Poisoning in Non-IID Federated Learning — COLLAPOIS | 2025-04-25 | OUTDATED |

Supplementary (corroboration only, not counted toward the 8):
- https://safeguard.sh/resources/blog/pypi-malicious-packages-2025-report — "PyPI Malicious Packages 2025 Report" (2025-03-28, OUTDATED)
- https://arxiv.org/html/2409.09368 — MalHug: "Models Are Codes" (ASE'24, 2024-10) `[legacy-context]` — still the best large-scale HF malicious-model measurement; frames the 2025 scanner-limitation debate [OUTDATED]
- https://dl.acm.org/doi/10.1145/3755881.3755921 — "Exploring Typo Squatting Threats in the Hugging Face Ecosystem" (Internetware 2025-07, OUTDATED)
- https://www.cs.columbia.edu/~junfeng/papers/pickleball-ccs25.pdf — PickleBall (CCS'25, OUTDATED) — safe-loaders-vs-benign-compat data
- https://arxiv.org/html/2505.10297v3 — FeRA federated backdoor defense (2025-05, OUTDATED); MARS (NeurIPS 2025) — adaptive-attack/defense state
- https://github.com/advisories/GHSA-wf7f-8fxf-xfxc — MLflow PyTorch flavor pickle RCE via pyfunc (2025, OUTDATED)
- https://github.com/mlflow/mlflow/issues/21083 — independent researcher confirmation that `mlflow.pyfunc.load_model()` doesn't propagate `weights_only=True` (created 2026-02-23, RECENT)

## CONCEPTS

### Model-format / serialization attack taxonomy
- [technique] PyTorch model files are ZIP archives wrapping pickled tensors; `torch.load()` executes pickle opcodes during deserialization. Malicious pickle can carry `REDUCE` with `os.system`, `GLOBAL` with `subprocess.Popen`, `eval`/`exec` — RCE on load. Formats with executable-deserialization risk: pickle, torch, joblib, dill, H5/HDF5, ONNX (metadata), TorchScript. (S2, S7, MalHug) [superseded-risk: attack mechanics stable, but torch.load() hardening (weights_only default) has advanced — re-verify which loaders still accept legacy pickles in 2026]
- [technique] Scanner evasion via container-level parser disagreement (nullifAI): the malicious PyTorch archive was compressed inside a 7z container. Picklescan's archive walker didn't recognize 7z magic bytes and silently skipped the file; `torch.load()` fell back to reading the inner pickle anyway. Defender saw nothing, consumer executed code. Generalizes: any mismatch between a scanner's file parser and the consumer's loader is an exploit seam. (S1) [superseded-risk: 2025-02 disclosure; HF taught Picklescan to scan 7z afterwards — container-evasion variants need 2026 re-verification]
- [technique] Payload-inside-model evasion for package registries: aliyun-ai-labs-snippets-sdk / ai-labs-snippets-sdk / aliyun-ai-labs-sdk shipped a fully functional infostealer inside a PyTorch model file, loaded from `__init__.py` at import time (~1,600 downloads in <24h before takedown). Model files are treated as "data" by legacy SCA tools, so they sail past source-only scanners. (S2)
- [technique] Configuration files are an overlooked code-execution vector on HF: file-operation keys (read/write arbitrary files), website-operation keys (fetch URLs → SSRF/IP disclosure), repository-operation keys (`_name_or_path` → redirect model loads to attacker-controlled repo → poisoned weights/backdoored scripts). Rule-based scan flagged 13,091 / 1,324 / 35,761 suspicious repos per category; LLM-assisted triage (ConfigScan) cut false positives while finding 2 new malicious repos. (S7) [superseded-risk: 2025-05 measurement; HF platform changes (config schema, trust-and-safety) unverified for 2026]
- [tool] Detection toolchain state: Picklescan (opcode deny-list, used by HF), ModelScan (multi-format), Fickling (pickle decompiler/rewriter, Trail of Bits), RL Spectra Assure THPs (TH19101/19103: serialized data creating processes; TH16103: base64 dynamic exec), ConfigScan (LLM-assisted), MalHug (dataset-script extraction + taint analysis, deployed on an Ant Group HF mirror: 91 malicious models + 9 malicious dataset loaders out of 705K models). (S1, S2, S7, MalHug) [superseded-risk: tool state is 2024–2025; re-check 2026 releases]
- [methodology] Deny-list scanning is structurally incomplete: ML workloads legitimately call thousands of callables from torch/numpy/transformers, so allow-lists break benign models (weights-only unpickler rejects ~15% of pickle-only HF repos — PickleBall), and deny-lists miss anything they never see. 2025 state: format-level policy beats opcode scanning — require safetensors, refuse pickle at ingress, verify Sigstore signatures via OpenSSF Model Signing v1.0 (shipped 2025-04, NVIDIA/HiddenLayer). (S1) [superseded-risk: OpenSSF Model Signing adoption status in 2026 unverified]
- [methodology] Treat every model artifact as code, not data: extension-based triage (.pkl/.pth/.pt/.h5/.joblib/.onnx → executable class), load only in sandboxes/containers with strace/network capture, keep an ML-BOM (CycloneDX) of models in the environment. (S2)

### Model registry / server attacks
- [technique] MLflow Tracking Server CVE-2025-11201 (ZDI-25-931): unauthenticated directory traversal in the `source` param of `/mlflow/model-versions/create` → arbitrary file write (drop `.py`/`.pth` into a `sys.path` directory) → RCE as the MLflow service account. Fix: `MLFLOW_CREATE_MODEL_VERSION_SOURCE_VALIDATION_REGEX` env var to constrain allowed source paths. Hunting signals: `../`, `..%2f`, `..%5c` in model-version API params; files appearing outside artifact-store dirs; anomalous writes by the mlflow service account. (S4) [superseded-risk: fix-era 2025-10; verify 2026 MLflow releases keep the validation default-on and no bypass of the regex env var is known]
- [technique] MLflow CVE-2025-15379: command injection at model-deploy time — with `env_manager=LOCAL`, dependency strings from the artifact's `python_env.yaml` are interpolated into a shell command unescaped. A malicious model artifact = arbitrary command execution on any system that deploys it. Fixed in 3.8.2 via `shlex` escaping; the fix was NOT backported to the 2.x branch (community issue #22429) so 2.x remains vulnerable. Hunting signals: shell metacharacters (`;`, `|`, `$()`, backticks) in `python_env.yaml`; unexpected process spawns from model-serving containers. (S5) [RECENT — 2026-04-02; superseded-risk: re-check whether 2.x branch is EOL/patched by 2026-08 and whether 3.8.2+ introduced regressions]
- [technique] Loader-wrapper deserialization inheritance: MLflow's `mlflow.pyfunc.load_model()` did not propagate `weights_only=True` to `torch.load()`, keeping a pickle-RCE path alive even after PyTorch hardened its own API (GHSA-wf7f-8fxf-xfxc; confirmed on Databricks Runtime 17.4.0 / MLflow 2.20.4, issue #21083). Lesson: audit every wrapper loader's deserialization defaults, not just the framework's. (S-supp) [RECENT — 2026-02-23; superseded-risk: issue closed 2026-02-25 — verify fix landed in MLflow 3.10.x+ and whether the check bypass persists in older supported releases]
- [methodology] The model registry is the supply-chain choke point: register one malicious artifact (or tamper with a version's `source`) and every downstream serve/score/deploy path executes it. Target-selection: exposed MLflow/registry UIs, `/mlflow/*` REST endpoints, unauthenticated model-version create APIs. Chain: registry write → deploy-time exec → ML-infra compromise. (S4, S5)

### Package registry / typosquatting
- [technique] AI-theme typosquatting wave on PyPI (early 2025): `deepseeek`/`deepseekai` (Jan 29 2025, dormant account created June 2023, infostealer exfiltrating env vars to a Pipedream C2, ~222 downloads); `aliyun-ai-labs-sdk` trio (May 2025); fake `transformers`/`pytorch`/`tensorflow`/`scikit-learn` variants and "helper" packages. ~30% of 500+ malicious packages removed from PyPI in early 2025 were AI/ML-themed; primary payload = credential theft (HF tokens, cloud creds, SSH keys, W&B/MLflow creds). (S3, S2, Safeguard-report) [superseded-risk: campaign wave is early-2025; 2026 PyPI/HF abuse patterns (and platform countermeasures) unverified]
- [technique] `setup.py` executes at install time — payload fires before first import; some packages bury payloads in "data files" (images/weights/configs) extracted and executed by the setup script to bypass source-level static analysis. (Safeguard-report)
- [methodology] Typosquatting hunting heuristics (from the DeepSeek case): dormant account with zero prior activity suddenly publishing; near-name variants of trending packages; low version numbers (0.0.8); download count vs. age mismatch; C2 on legitimate platforms (Pipedream) to dodge infra blocking; AI-generated code detectable by characteristic explanatory comments. (S3)
- [technique] HF hub typosquatting at scale: 1,574 squatting models vs top-100 downloaded (10.4% malicious), 625 squatting datasets (42.2% impersonation), 302 squatting orgs — HF's automation-driven load (no manual review before `from_pretrained`/`load_dataset` executes) makes it structurally more exposed than PyPI/GitHub. Malicious models referencing typosquatted datasets amplify impact across the dependency chain. (Internetware-2025-supp)

### Token / credential exposure in ML repos
- [technique] Hardcoded HF tokens with privileged (write) permissions in public model repos enable org-wide supply chain compromise: LLaVA-NeXT leaked a token with privileged rights; attackers could modify/publish models under HF orgs `llms-lab`, `LongVa`, `Evo-LMM`. Tenable's stance: treat all artifacts of affected orgs as untrusted. Hunting: regex-scan repos for `hf_[A-Za-z0-9]+` tokens, verify token permissions/org membership, and treat write-scoped tokens as RCE-equivalent. (S6) [superseded-risk: org status as of 2026 unverified; technique (write-scoped token = RCE-equivalent) remains]

### Dataset poisoning / federated learning
- [technique] Collaborative backdoor poisoning (COLLAPOIS, 2025): a single pre-trained trojaned model distributed to a few compromised clients; their coordinated gradients pull the global model into the trojan's low-loss region. Works with ~0.5% compromised clients (70%+ backdoor success on 15% of benign clients under robust FL training); exploits non-IID scattered gradients that make malicious updates look like normal client diversity. (S8)
- [technique] Adaptive backdoors now mimic benign update statistics (3DFed decoy updates, DarkFed cosine-similarity constraints, LGA layer-wise gradient alignment vs. previous global update) and defeat OOD/anomaly defenses; 2025 defense research therefore moved to behavior-consistency detection (MARS backdoor energy, FeRA representation-variance consistency + MAD-based norm-inflation filter, SPMC marginal contribution). Detection methodology: distrust round-level statistical outliers; track cross-round consistency and per-layer norm distributions. (S8, FeRA/MARS-supp) [superseded-risk: FL attack/defense state is 2025; no 2026 follow-up in cluster]

## OUTDATED-OR-SUPERSEDED

Re-tiering note: with the 2026-06-01 CURRENT cutoff, this cluster is fully OUTDATED-tier except two RECENT fix-tracking entries. The attack classes remain relevant as legacy baselines, but every item needs 2026 re-verification before it can drive current engagements.

- "Picklescan-style deny-lists are an adequate model gate" (2022–2024 era) → superseded by nullifAI (2025-02): container-level evasion means the scanner never sees the bytes; deny-lists are structurally incomplete. 2025-2026 state: safetensors-only + Sigstore model signing. [superseded-risk: re-verify 2026 HF scanner + model-signing adoption]
- "Hugging Face scans models for malware" → HF's scanner flagged only ~38% of unsafe-serialization model files (pickle-only focus); 2025 research (MalHug, ConfigScan) shows datasets, config files, and loading scripts are the growth vector, not just model weights. [superseded-risk: HF policy/scanner changes in 2026 unverified]
- "MLflow's problem class was auth/static-file traversal" (CVE-2023-1177, CVE-2023-6018, CVE-2024-1483) → 2025 turned the registry into a first-class unauthenticated RCE surface (traversal→file-write→RCE, deploy-time command injection). [superseded-risk: CVE-2025-11201/15379 fix-state in 2026 MLflow releases needs re-check]
- "Safe loaders (weights_only) are the ecosystem fix" → PickleBall shows weights-only rejects ~15% of benign pickle repos; loader wrappers (MLflow pyfunc) silently reintroduce unsafe defaults. [superseded-risk: MLflow #21083 fixed 2026-02 — verify propagation of weights_only through other wrappers]
- "Typosquatting targeted infra tooling" → 2025 wave is AI/ML-themed, credential-focused, increasingly AI-generated code with C2 on legitimate platforms. [superseded-risk: 2025 campaign data; 2026 wave unmeasured in this cluster]
- Platform note: huntr's OSV program (a major disclosure path for MLflow-class CVEs) was sunset 2026-06-30/locked 2026-07-31 (huntr 2.0 pivot, 2026-06-08) — `vuln-intel`/`auto-research` reliance on huntr hacktivity as a CVE feed is affected; GHSA/NVD become the primary remaining feeds. See huntr-community.md audit for details.

## How this changes our harness
- **recon/domain-model**: for any target with an ML component, add model-registry discovery (exposed MLflow/registry UIs, `/mlflow/*` endpoints, model-version create APIs) and unsafe-model-file inventory (`.pkl/.pth/.pt/.h5/.joblib/.onnx`) to the surface map.
- **nuclei-scanner**: new templates for CVE-2025-11201 (traversal in `source` param, unauthenticated) and CVE-2025-15379 (python_env.yaml shell-metachar check on downloaded artifacts) — both are safe to check actively. [superseded-risk: re-verify against current MLflow versions before shipping templates]
- **osint**: add AI-theme typosquatting hunt (near-name diff of target-adjacent packages, dormant-account heuristics, `hf_*` token regex scan of public repos, org-membership checks per Tenable TRA-2025-16).
- **rce/technique-kb**: new entries — pickle opcode injection, container-level scan-evasion, registry source traversal→write→RCE, deploy-time env command injection, config-file attack keys, collaborative FL poisoning; map each to evidence signals and verify workflows.
- **impact-verifier/reporting**: artifact-loading evidence must come from sandboxed loads (container + strace/network capture); never load untrusted pickles on the host. Treat write-scoped HF tokens as RCE-equivalent impact.
- **campaign**: when the target serves/downloads models, include registry + artifact-vetting steps in the plan; cap artifact-execution tests at active-safe (sandbox), file-write exploitation at intrusive-with-scope-file.
