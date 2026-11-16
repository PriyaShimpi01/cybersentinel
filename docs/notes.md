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

Therefore, PR-AUC is particularly useful for evaluating CyberSentinel's attack detection models. ROC-AUC should also be reported for a more complete evaluation.