
# Project Title

## Problem Statement

Authorization systems tell you whether an action is permitted, not whether it is normal. CyberSentinel adds a behavioral layer: three detectors for network intrusion, insider threat and ransomware, a context engine, and a correlation layer that turns many weak alerts into a few explainable incidents, so SOC analysts spend time on real threats.

IAM answers "is this action permitted?" It cannot answer "is this action normal for this person?"

## Objective

Briefly explain what you aim to build.
we aim to buid a software which analyses behaviour and understand pattern of common cyber threts. It reduces alert fatigue and makes th job easier for SOC analysts.

Data Sources → Preprocessing → three detectors → Common Event Schema → Context Engine → Correlation and Risk Scoring → Analyst Dashboard.

## Technologies Used

- Python
- Pandas
- NumPy

## Project Structure

- data/: Dataset storage
- notebooks/: Experiments
- src/: Source code
- tests/: Test cases
- configs/: Configuration files


## Phase 2: Insider Threat (SYNTHETIC DATA)
- CERT download failed, so I generated 150 users x 90 days with 8 injected insiders (120 malicious user-days, 0.9%). Results show the METHOD works, not real-world performance. The attacks are injected by me.
- Isolation Forest trained on clean early days (no labels).
- First result (intensity 1.0): raw counts PR-AUC 0.983, per-user rolling z-scores 0.577, random baseline 0.027. 8/8 insiders flagged by per-user scores in top 5%.
- My hypothesis (per-user features win) was NOT supported. Possible reasons: (1) injected attacks are large in absolute terms, (2) rolling baseline absorbs the attack ("baseline poisoning").
- Follow-up: compared four feature sets at three attack strengths (PR-AUC):
  | Intensity | Raw | Rolling z | Frozen z | Raw+Frozen |
  |---|---|---|---|---|
  | 1.0 | 0.983 | 0.577 | 0.985 | 0.986 |
  | 0.5 | 0.735 | 0.426 | 0.819 | 0.797 |
  | 0.25 | 0.284 | 0.200 | 0.471 | 0.386 |
- Rolling baseline was worst everywhere: the insider's own bad days contaminate the baseline ("baseline poisoning"). A frozen baseline learned from clean days avoids this.
- Per-user baselines matter most for subtle attacks. For obvious attacks, raw counts are enough.
- Hybrid (raw + frozen) did not beat frozen alone (my prediction was wrong).
- Limits: single seed, 8 insiders, synthetic. At intensity 0.25 recall in the top 5% was only 63%. A frozen baseline needs periodic refresh in production.
- Limitation: synthetic data. Real insiders are subtler and noisier.
