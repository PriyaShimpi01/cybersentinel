import csv
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

# ---------- paths: built from this file's location, so it works from any folder ----------
ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "processed"
FEEDBACK = DATA / "feedback.csv"

st.set_page_config(page_title="CyberSentinel", layout="wide")

# ---------- load data once; Streamlit caches it so clicks stay fast ----------
@st.cache_data
def load():
    inc = pd.read_csv(DATA / "incidents.csv", index_col="incident_id")
    ev = pd.read_csv(DATA / "events.csv", parse_dates=["timestamp"])
    return inc, ev

inc, ev = load()

# ---------- simulated response playbook (recommendations only, nothing is executed) ----------
PLAYBOOK = {
    "PortScan":      ["Block the scanning source at the firewall", "Review exposed services on the host"],
    "BruteForce":    ["Force a password reset for targeted accounts", "Enable MFA", "Rate-limit login attempts"],
    "WebAttack":     ["Review web server logs for the affected endpoint", "Enable WAF rules"],
    "DoS":           ["Enable rate limiting on the affected service", "Notify the network team"],
    "DDoS":          ["Enable upstream DDoS protection", "Notify the network team"],
    "Bot":           ["Isolate the host from the network", "Scan for malware"],
    "InsiderMisuse": ["Review the user's recent file access and USB activity", "Notify the user's manager and HR per policy", "Temporarily restrict removable-media access"],
    "Ransomware":    ["ISOLATE the host immediately", "Disable the affected account", "Verify backups are intact"],
}
ORDER = ["Ransomware", "InsiderMisuse", "Bot", "BruteForce", "WebAttack", "DoS", "DDoS", "PortScan"]  # most urgent first

# ---------- feedback helpers ----------
def save_feedback(incident_id, entity, verdict, note):
    new = not FEEDBACK.exists()
    with open(FEEDBACK, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["time", "incident_id", "entity", "verdict", "note"])
        w.writerow([datetime.now().isoformat(timespec="seconds"), incident_id, entity, verdict, note])

def load_feedback():
    if FEEDBACK.exists():
        return pd.read_csv(FEEDBACK)
    return pd.DataFrame(columns=["time", "incident_id", "entity", "verdict", "note"])

fb = load_feedback()

# ---------- header ----------
st.title("CyberSentinel: Analyst Dashboard")
st.caption("Prototype on SIMULATED data. Detectors were trained on CIC-IDS2017 and synthetic data; "
           "host and time assignments are simulated. Recommendations are not executed.")

with st.expander("How to read this dashboard", expanded=True):
    st.markdown("""
- **Alert:** one suspicious thing a detector noticed. **Incident:** all alerts on one machine within 24 hours, merged.
- **Risk score:** how worried the system is (0 to 1). Many are close to 1, so also look at the attack stages.
- **Attack stages:** how many steps of an attack were seen (scan, credential attack, misuse, damage). More stages means more concerning.
- **Severity:** my own rule: 3 or more stages is CRITICAL, 2 is HIGH, otherwise MEDIUM.
- Everything here is simulated; the response buttons never run anything.
""")

# ---------- sidebar: filters ----------
st.sidebar.header("Filters")
min_score = st.sidebar.slider("Minimum incident score", 0.0, 1.0, 0.5, 0.01)
all_types = sorted(ev["threat_type"].unique())
types = st.sidebar.multiselect("Threat types present", all_types, default=[])
min_stages = st.sidebar.slider("Minimum kill-chain stages", 0, 4, 0)
hide_reviewed = st.sidebar.checkbox("Hide already-reviewed incidents", value=False)
demo = st.sidebar.checkbox("Demo mode: show ground truth", value=False)

view = inc[(inc["incident_score"] >= min_score) & (inc["n_stages"] >= min_stages)]
if types:
    ok_ids = set(ev[ev["threat_type"].isin(types)]["incident_id"])
    view = view[view.index.isin(ok_ids)]
if hide_reviewed and len(fb):
    view = view[~view.index.isin(fb["incident_id"])]
view = view.sort_values("incident_score", ascending=False)

def severity(r):
    if r["n_stages"] >= 3: return "CRITICAL"
    if r["n_stages"] == 2: return "HIGH"
    return "MEDIUM"

view = view.assign(severity=view.apply(severity, axis=1))

# ---------- top-level numbers ----------
c1, c2, c3, c4 = st.columns(4)
c1.metric("Raw alerts", f"{len(ev):,}")
c2.metric("Incidents", f"{len(inc):,}")
c3.metric("Shown after filters", f"{len(view):,}")
c4.metric("Reviewed by analyst", f"{fb['incident_id'].nunique():,}")

# ---------- incident table ----------
st.subheader("Incidents, highest risk first")
cols = ["severity", "entity", "incident_score", "n_events", "n_types", "n_stages"] + (["true"] if demo else [])
st.dataframe(
    view[cols].head(200),
    width="stretch",
    column_config={
        "severity": "Severity",
        "entity": "Machine",
        "incident_score": st.column_config.ProgressColumn("Risk score", min_value=0.0, max_value=1.0, format="%.4f"),
        "n_events": "Alerts merged",
        "n_types": "Threat kinds",
        "n_stages": "Attack stages",
    },
)
if view.empty:
    st.info("No incidents match these filters.")
    st.stop()

# ---------- pick one incident ----------
options = list(view.head(200).index)
labels = {i: f"#{i} | {view.loc[i, 'entity']} | score {view.loc[i, 'incident_score']:.5f}" for i in options}
sel = st.selectbox("Open an incident", options, format_func=lambda i: labels[i])
row = inc.loc[sel]
g = ev[ev["incident_id"] == sel]

st.divider()
left, right = st.columns([3, 2])

with left:
    st.subheader(f"Incident #{sel} on {row['entity']}")

    summ = (g.groupby(["threat_type", "technique"])
              .agg(events=("event_id", "count"), first_seen=("timestamp", "min"),
                   last_seen=("timestamp", "max"), peak_score=("score", "max"))
              .reset_index().sort_values("first_seen"))
    sev = severity(row)
    story = " → ".join(summ["threat_type"])
    {"CRITICAL": st.error, "HIGH": st.warning, "MEDIUM": st.info}[sev](
        f"**{sev}.** Order of events on this machine: **{story}**")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Risk score", f"{row['incident_score']:.5f}")
    m2.metric("Alerts merged", f"{int(row['n_events']):,}")
    m3.metric("Threat kinds", int(row["n_types"]))
    m4.metric("Attack stages", int(row["n_stages"]))

    st.markdown("**Why it was flagged (model evidence):**")
    for line in str(row["explanation"]).split("\n"):
        st.markdown(f"- {line}")

    st.markdown("**Timeline by threat type:**")
    st.dataframe(summ, width="stretch")

    if g["off_hours"].any() or g["sensitive"].any():
        flags = []
        if g["off_hours"].any(): flags.append("activity outside working hours")
        if g["sensitive"].any(): flags.append("a sensitive host")
        st.warning("Context raised this score: " + " and ".join(flags) + ". "
                   "All actions were authorized by IAM; the system flags them because of behavior, not permission.")

    if demo:
        st.info(f"Ground truth: this incident {'DOES' if row['true'] == 1 else 'does NOT'} contain a real attack.")

with right:
    st.subheader("Recommended response (simulated)")
    present = [t for t in ORDER if t in set(g["threat_type"])]
    if not present:
        st.write("No playbook for this incident's alert types. Review manually.")
    for t in present:
        st.markdown(f"**If {t} is confirmed:**")
        for a in PLAYBOOK[t]:
            st.markdown(f"- {a}")
    st.caption("Recommendations only. Nothing is executed.")

    st.subheader("Analyst decision")
    note = st.text_input("Optional note", key=f"note_{sel}")
    b1, b2 = st.columns(2)
    if b1.button("Mark false positive", key=f"fp_{sel}"):
        save_feedback(sel, row["entity"], "false_positive", note)
        st.success("Saved as false positive.")
    if b2.button("Confirm threat", key=f"ok_{sel}"):
        save_feedback(sel, row["entity"], "confirmed", note)
        st.success("Saved as confirmed.")

    prev = load_feedback()
    prev = prev[prev["incident_id"] == sel]
    if len(prev):
        st.markdown("**Previous decisions on this incident:**")
        st.dataframe(prev[["time", "verdict", "note"]], use_container_width="stretch")