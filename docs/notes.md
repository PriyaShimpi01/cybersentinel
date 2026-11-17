# MITRE ATT&CK Technique Mapping – CyberSentinel

This document maps selected MITRE ATT&CK techniques to CyberSentinel's planned detection models and the observable signals that could indicate suspicious activity.

**Note:** These are proposed detection mappings. The models and detection capabilities are not yet implemented.


# MITRE ATT&CK Technique Mapping – CyberSentinel

| Technique | ID | Tactic | Proposed CyberSentinel Model | Observable Signal |
|---|---|---|---|---|
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | Credential Access | Network Intrusion Detector | Repeated failed login attempts from the same IP or against multiple accounts within a short period, possibly followed by a successful login. |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | Initial Access, Persistence, Privilege Escalation, Defense Evasion | Insider Threat Detector + Context Engine | A valid employee account logs in from an unusual location or outside normal working hours, accesses unfamiliar systems, or performs unexpected privileged actions. |
| Exfiltration Over Physical Medium | [T1052](https://attack.mitre.org/techniques/T1052/) | Exfiltration | Insider Threat Detector | Large or sensitive file copies to a removable USB device, especially outside work hours or by a user who does not normally access those files. |
| Data Encrypted for Impact | [T1486](https://attack.mitre.org/techniques/T1486/) | Impact | Ransomware Detector | Rapid, repeated file modifications or encryption across many files, unusual file extensions, and possible ransom note creation. |
| Network Denial of Service | [T1498](https://attack.mitre.org/techniques/T1498/) | Impact | Network Intrusion Detector | Sudden abnormal increase in network traffic, packet rate, or connection requests directed at a server, potentially exhausting its bandwidth or resources. |


## 2. Detection Design Notes

- **Network Intrusion Detector:** Focuses on suspicious authentication patterns, network traffic anomalies, and denial-of-service behavior.
- **Insider Threat Detector:** Focuses on unusual user behavior, sensitive file access, and suspicious data transfers.
- **Ransomware Detector:** Focuses on rapid file encryption, unusual file modifications, and ransomware-related activity.
- **Context Engine:** Evaluates user identity, access history, working hours, device information, and other contextual signals.
- **Correlation Layer:** Combines related alerts from different detectors into explainable security incidents.

## 3. Important Considerations

- A single unusual event does not automatically confirm an attack.
- Detection should consider user baselines, historical behavior, device identity, and event context.
- The same MITRE technique may be detected by more than one model.
- The system should explain which signals contributed to an alert and why it was flagged.

**Reference:** [MITRE ATT&CK Enterprise Techniques](https://attack.mitre.org/techniques/enterprise/)


# Evaluation Metrics for CyberSentinel

## 1. Confusion Matrix

| Prediction | Actual Attack | Actual Normal |
|---|---:|---:|
| Predicted Attack | TP = 80 | FP = 70 |
| Predicted Normal | FN = 20 | TN = 9830 |

### Understanding the terms

- **TP (True Positive):** Real attacks correctly detected.
- **FP (False Positive):** Normal events incorrectly flagged as attacks.
- **FN (False Negative):** Real attacks missed by the model.
- **TN (True Negative):** Normal events correctly classified.

## 2. Evaluation Metrics

### 1. Accuracy
- **Meaning:** Percentage of all predictions that are correct.
- **Formula:** `(TP + TN) / Total`
- **Example:** Out of 10,000 events, how many did we classify correctly?

### 2. Precision
- **Meaning:** Of all the alerts generated, how many are genuine attacks?
- **Formula:** `TP / (TP + FP)`
- **Example:** Of 150 brute-force alerts, how many were actual brute-force attempts?

### 3. Recall (Sensitivity)
- **Meaning:** Of all actual attacks, how many did we detect?
- **Formula:** `TP / (TP + FN)`
- **Example:** Of the real brute-force attempts, how many did we catch?

### 4. F1-score
- **Meaning:** Harmonic mean of precision and recall.
- **Formula:** `2 * (Precision * Recall) / (Precision + Recall)`
- **Example:** How well does the model balance attack detection and alert reliability?

### 5. False Positive Rate (FPR)
- **Meaning:** Percentage of normal events incorrectly flagged as attacks.
- **Formula:** `FP / (FP + TN)`
- **Example:** Out of all legitimate login attempts, how many were incorrectly flagged?

### 6. Specificity
- **Meaning:** Percentage of normal events correctly identified as normal.
- **Formula:** `TN / (TN + FP)`
- **Example:** Out of all legitimate events, how many did we correctly ignore?

## 3. ROC-AUC

- Plots True Positive Rate (TPR) against False Positive Rate (FPR).
- Measures the model's ability to distinguish positive and negative classes across different classification thresholds.

## 4. PR-AUC

- Plots Precision against Recall.
- Focuses on positive-class detection and alert reliability.

## 5. Why PR-AUC is Important for CyberSentinel

CyberSentinel works with imbalanced cybersecurity data where normal events greatly outnumber attacks.

ROC-AUC can appear high even when the model generates many false alerts because the number of normal events is very large.

PR-AUC highlights the relationship between genuine attack detection and false alerts.




## Phase 1b: All Days and Cross-Day Evaluation

### Data
- 8 files, 2,827,876 rows before cleaning, 2,497,980 after removing duplicates.
- Grouped labels into 7 families: BENIGN, BruteForce (FTP/SSH-Patator), DoS, DDoS, PortScan, WebAttack, Bot.
- Dropped Infiltration (36 rows): too few to learn or test fairly.

### Results
| Experiment | PR-AUC | Recall | Precision |
|---|---|---|---|
| A: random split, all days | 0.9999 | 0.9995 | 0.9952 |
| B: train Mon-Thu, test Fri (unseen attacks) | 0.7906 | 0.0066 | 0.9613 |
| B2: B without Destination Port | 0.7390 | 0.0021 | 0.8070 |
| C: Mon-Thu + first half of Fri, test second half | 0.9986 | 0.9903 | 0.9997 |
| Isolation Forest (Monday normal only), test Fri | 0.456 | at FPR 1%: 0.0000 | n/a |

Per-family recall after adding labeled Friday data: DDoS 99.97%, PortScan 99.5%, Bot 47.3% (few examples).

Findings:
- Labeled examples fix the unseen-attack problem (recall 0.7% -> 99%), which is why CyberSentinel needs an analyst feedback loop that retrains on labeled incidents.
- Isolation Forest on raw flow features performed near random (PR-AUC 0.456 vs baseline ~0.36). Flow features vary too much between days. Anomaly detection fits better on per-user behavior, which is the insider-threat model.
- Experiment C is optimistic: halves of the same file are similar.

### Key finding
A random split gives 99.99%, but on a different day with unseen attacks recall fell to 0.7%. The model learned the attacks it was shown, not "attacks" in general. Per attack: Bot 0%, DDoS 0.8%, PortScan 0.5%.

### Threshold tuning
At the default 0.5 threshold, recall was under 1%. With a false-alarm budget of 0.1% FPR, recall was 31%; at 1% it was 40%; at 5% it was 50%. The model ranks attacks as more suspicious than normal but with small scores, so choosing the threshold matters.

### What this means for CyberSentinel
- Supervised detection is strong on attack types it has seen and weak on new ones.
- Hence: (1) an anomaly-based detector alongside it, (2) an analyst feedback loop that retrains on newly labeled attacks, (3) correlation to combine weak signals.

### What I have NOT proven
- All CIC-IDS2017 data comes from one lab network over five days.
- Experiment C is optimistic because halves of the same file are similar.
- I cannot say how the model performs on real production traffic.


- v2 ransomware (mixed stealth in training, bulk-rename confounder, baseline + sustained features): PR-AUC 1.000, recall at 1% FPR = 1.0 at stealth 1.0/0.5/0.2.
- Perfect because (a) the model trains on all stealth levels, like Experiment C, and (b) train and test come from the same simulator, so the model can learn the generator's parameters. This shows the simulator is separable, not real-world performance.
- Single-window vs +baseline&sustained features cannot be compared (both perfect).
- False-alarm rate: compress 2.6%, bulk_rename 1.8%, update 0.27%, backup 0.12%, office 0.13%. Confounders cause most false alarms.
- Held-out stealth test: trained without stealth 0.2, tested on it: recall at 1% FPR = 5.9% (vs 100% at 1.0 and 0.5, which were in training). A model only recognizes ransomware speeds it has seen. This supports retraining on analyst-labelled incidents.
- Limitation: synthetic; real ransomware differs.