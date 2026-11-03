const pptxgen = require("pptxgenjs");
const { applyTheme } = require("/mnt/skills/public/pptx/scripts/apply_theme.js");
const fs = require("fs");
const cov = JSON.parse(fs.readFileSync("coverage/coverage_data.json"));
const res = JSON.parse(fs.readFileSync("results/rule_test_results.json"));
const THEME = { name: "ThreatShield", headFontFace: "Georgia", bodyFontFace: "Calibri",
  colors: { dk1: "0B1F2A", lt1: "FFFFFF", dk2: "12343B", lt2: "EEF3F2", accent1: "0E7C86", accent2: "F2A541", accent3: "D64545", accent4: "3FA34D", accent5: "6B7A8F", accent6: "1C3D5A", hlink: "0E7C86", folHlink: "6B7A8F" } };
const pres = new pptxgen(); pres.layout = "LAYOUT_16x9"; pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
pres.title = "Cyberion ThreatShield - Final Presentation"; pres.author = "Madhan";
const C = pres.SchemeColor;

pres.defineSlideMaster({ title: "DARK", background: { color: "0B1F2A" }, objects: [
  { placeholder: { options: { name: "title", type: "title", x: 0.6, y: 1.5, w: 8.8, h: 1.3, fontFace: THEME.headFontFace, fontSize: 36, bold: true, color: "FFFFFF", valign: "top", margin: 0 }, text: "" } } ] });
pres.defineSlideMaster({ title: "LIGHT", background: { color: "FFFFFF" }, objects: [
  { placeholder: { options: { name: "title", type: "title", x: 0.6, y: 0.35, w: 8.8, h: 0.8, fontFace: THEME.headFontFace, fontSize: 26, bold: true, color: "0B1F2A", valign: "middle", margin: 0 }, text: "" } },
  { rect: { x: 0.6, y: 1.18, w: 0.9, h: 0.05, fill: { color: "0E7C86" } } },
  { text: { text: "Cyberion ThreatShield | Madhan", options: { x: 0.6, y: 5.25, w: 5, h: 0.25, fontSize: 9, color: "6B7A8F", margin: 0 } } } ] });

function card(s, x, y, w, h, big, small, col) {
  s.addShape(pres.ShapeType.roundRect, { x, y, w, h, fill: { color: "EEF3F2" }, line: { color: "EEF3F2" }, rectRadius: 0.08, objectName: "card" });
  s.addText(big, { x: x + 0.15, y: y + 0.12, w: w - 0.3, h: h * 0.5, fontFace: THEME.headFontFace, fontSize: 30, bold: true, color: col, margin: 0, isTextBox: true, valign: "middle" });
  s.addText(small, { x: x + 0.15, y: y + h * 0.58, w: w - 0.3, h: h * 0.38, fontSize: 12, color: "12343B", margin: 0, isTextBox: true, valign: "top" });
}
// 1 Title
let s = pres.addSlide({ masterName: "DARK" });
s.addText("Cyberion ThreatShield", { placeholder: "title" });
s.addText("Detection Engineering & Threat Hunting", { x: 0.6, y: 2.75, w: 8.8, h: 0.5, fontSize: 22, color: "F2A541", margin: 0, isTextBox: true });
s.addText("Internmo internship project | Madhan | 22 Sigma rules, 4 correlations, validated on 37,364 real Windows events", { x: 0.6, y: 3.4, w: 8.8, h: 0.8, fontSize: 14, color: "CADCFC", margin: 0, isTextBox: true });
s.addNotes("Single-analyst detection engineering engagement. All results come from running rules against real attack telemetry, not assumptions.");
// 2 Summary
s = pres.addSlide({ masterName: "LIGHT" }); s.addText("Result: every rule fired on real attack logs", { placeholder: "title" });
card(s, 0.6, 1.5, 2.8, 1.5, "26 / 26", "rules (22 + 4 correlation) matched real events; sigma check: 0 errors", "0E7C86");
card(s, 3.6, 1.5, 2.8, 1.5, "32", "ATT&CK v20 techniques assessed across 9 tactics", "1C3D5A");
card(s, 6.6, 1.5, 2.8, 1.5, "2 + 2 + 3", "threat hunts, incident cases, IR playbooks", "D64545");
s.addText([{ text: "Coverage: 12 covered, 10 partial, 10 not covered.", options: { bold: true, breakLine: true } },
  { text: "Honest limits: attack-only data (no false-positive rate), short captures, own test harness.", options: {} }],
  { x: 0.6, y: 3.35, w: 8.8, h: 1.2, fontSize: 16, color: "0B1F2A", margin: 0, isTextBox: true, paraSpaceAfter: 8 });
s.addNotes("Lead with the evidence: 26 of 26 rules fire on genuine attack data. Then name the limits so the audience trusts the numbers.");
// 3 Pipeline
s = pres.addSlide({ masterName: "LIGHT" }); s.addText("Approach: evidence before claims", { placeholder: "title" });
const steps = [["1 Parse", "278 EVTX files to 37,364 events"], ["2 Author", "Sigma rules mapped to ATT&CK v20"], ["3 Test", "Own harness runs rules on real data"], ["4 Hunt", "Hypotheses, negative results kept"], ["5 Investigate", "Timelines to closure class"], ["6 Report", "Matrix, playbooks, exec summary"]];
steps.forEach((t, i) => { const x = 0.6 + (i % 3) * 3.0, y = 1.55 + Math.floor(i / 3) * 1.65;
  s.addShape(pres.ShapeType.roundRect, { x, y, w: 2.8, h: 1.4, fill: { color: i % 2 ? "12343B" : "0E7C86" }, line: { color: "FFFFFF", width: 0 }, rectRadius: 0.08, objectName: "step" });
  s.addText(t[0], { x: x + 0.15, y: y + 0.12, w: 2.5, h: 0.45, fontFace: THEME.headFontFace, fontSize: 18, bold: true, color: "FFFFFF", margin: 0, isTextBox: true });
  s.addText(t[1], { x: x + 0.15, y: y + 0.62, w: 2.5, h: 0.7, fontSize: 13, color: "FFFFFF", margin: 0, isTextBox: true, valign: "top" }); });
s.addNotes("The key discipline: every Covered entry on the matrix is asserted in code to trace to a rule that fired.");
// 4 Data
s = pres.addSlide({ masterName: "LIGHT" }); s.addText("Telemetry: real logs, 4 channels", { placeholder: "title" });
s.addChart(pres.charts.BAR, [{ name: "Events", labels: ["Sysmon", "Security", "BITS-Client", "RDP Core", "Application"], values: [3241, 1577, 1548, 794, 393] }],
  { x: 0.6, y: 1.45, w: 5.2, h: 3.6, barDir: "bar", chartColors: ["0E7C86"], showValue: true, dataLabelPosition: "outEnd", dataLabelFontSize: 11, catAxisLabelFontSize: 12, valAxisHidden: true, valGridLine: { style: "none" }, showTitle: true, title: "Events by channel (top 5 of 8 channels)", titleFontSize: 11, showLegend: false });
s.addText([{ text: "278 EVTX files (EVTX-ATTACK-SAMPLES)", options: { bullet: true, breakLine: true } }, { text: "37,364 events, 22 lab hosts", options: { bullet: true, breakLine: true } },
  { text: "Pre-recorded attacks, some by Atomic Red Team; I did not generate telemetry", options: { bullet: true, breakLine: true } }, { text: "Sysmon 1/3/8/10/12/13, Security 4624/4662/4698/5145, PowerShell 4104", options: { bullet: true } }],
  { x: 6.0, y: 1.6, w: 3.4, h: 3.2, fontSize: 13, color: "0B1F2A", margin: 0, isTextBox: true, paraSpaceAfter: 8, valign: "top" });
// 5 Coverage chart
s = pres.addSlide({ masterName: "LIGHT" }); s.addText("ATT&CK v20 coverage by tactic", { placeholder: "title" });
const tactics = {}; cov.forEach(c => c.tactics.forEach(t => { tactics[t] = tactics[t] || { Covered: 0, "Partially Covered": 0, "Not Covered": 0 }; tactics[t][c.status]++; }));
const names = Object.keys(tactics).sort((a, b) => Object.values(tactics[b]).reduce((x, y) => x + y) - Object.values(tactics[a]).reduce((x, y) => x + y));
s.addChart(pres.charts.BAR, ["Covered", "Partially Covered", "Not Covered"].map(k => ({ name: k, labels: names, values: names.map(n => tactics[n][k]) })),
  { x: 0.6, y: 1.4, w: 8.8, h: 3.7, barDir: "col", barGrouping: "stacked", chartColors: ["3FA34D", "F2A541", "D64545"], showLegend: true, legendPos: "b", legendFontSize: 11, catAxisLabelFontSize: 10, valAxisLabelFontSize: 10, showValue: true, dataLabelColor: "FFFFFF", dataLabelFontSize: 10, dataLabelPosition: "ctr", valGridLine: { color: "E1E8E7", size: 0.5 } });
s.addNotes("Counts are per tactic; a technique appears under each tactic it belongs to in ATT&CK v20. Defense Evasion no longer exists: it is Stealth plus Defense Impairment.");
// 6 Taxonomy finding
s = pres.addSlide({ masterName: "LIGHT" }); s.addText("Finding: ATT&CK moved under my feet", { placeholder: "title" });
s.addText([{ text: "pySigma's tag check rejected attack.defense-evasion and T1070.001.", options: { bullet: true, breakLine: true } },
  { text: "Verified on attack.mitre.org: Defense Evasion split into Stealth (TA0005) and Defense Impairment (TA0112); T1070.001 is now T1685.005.", options: { bullet: true, breakLine: true } },
  { text: "Pulled the official v20 STIX data and re-mapped every rule and matrix row from it, not from memory.", options: { bullet: true, breakLine: true } },
  { text: "Result: 0 tagging errors; Stealth and Defense Impairment tracked separately.", options: { bullet: true } }],
  { x: 0.6, y: 1.5, w: 8.8, h: 3.4, fontSize: 17, color: "0B1F2A", margin: 0, isTextBox: true, paraSpaceAfter: 12, valign: "top" });
// 7 Validation honesty
s = pres.addSlide({ masterName: "LIGHT" }); s.addText("Validation: where I was wrong", { placeholder: "title" });
const hdr = { bold: true, color: "FFFFFF", fill: { color: "12343B" }, fontSize: 12 };
const rows = [[{ text: "Rule", options: hdr }, { text: "Expected", options: hdr }, { text: "What the data showed", options: hdr }, { text: "Action", options: hdr }],
  ["DET-004", "Renamed regsvr32 fires", "jabber.exe /i:http, no scrobj", "Added /i:http variant"], ["DET-007", "osk sample fires", "Sample has no IFEO key write", "Added reg.exe variant, coverage Partial"],
  ["DET-008", "Run key sample fires", "Path was C:\\Windows\\Tasks", "Added path"], ["DET-012", "WMI 4688 sample fires", "No parent field in 4688", "Documented gap"], ["DET-003", "Filter services.exe", "Only hits = PPLdump attack", "Filter reverted"]];
s.addTable(rows.map((r, i) => i === 0 ? r : r.map(t => ({ text: t, options: { fontSize: 11, color: "0B1F2A" } }))), { x: 0.6, y: 1.5, w: 8.8, colW: [1.1, 2.2, 3.0, 2.5], border: { type: "solid", pt: 0.5, color: "CCD6D5" }, fill: { color: "FFFFFF" }, rowH: 0.5, valign: "middle" });
s.addNotes("This slide is the integrity argument. A rule that fires is not proof of a good rule; checking against where it should fire found 5 problems.");
// 8 Hunts
s = pres.addSlide({ masterName: "LIGHT" }); s.addText("Hunts: one confirmed, one open", { placeholder: "title" });
card(s, 0.6, 1.5, 4.3, 1.6, "CONFIRMED", "HUNT-01 COM hijacking (T1546.015): 14 CLSID writes narrowed to 5; Firefox and Outlook-style hijacks found. New rule DET-021.", "3FA34D");
card(s, 5.1, 1.5, 4.3, 1.6, "INCONCLUSIVE", "HUNT-02 beaconing: max 2 connections per tuple, too short to test. Pivot found LOLBins downloading payloads. New rule DET-022.", "F2A541");
s.addText("Negative results are reported, not hidden: no beacon-like groups, and the 9 benign .NET COM registration events were ruled out.", { x: 0.6, y: 3.45, w: 8.8, h: 1, fontSize: 15, color: "0B1F2A", margin: 0, isTextBox: true, valign: "top" });
// 9 Cases
s = pres.addSlide({ masterName: "LIGHT" }); s.addText("Two cases taken to closure", { placeholder: "title" });
card(s, 0.6, 1.5, 4.3, 1.75, "CASE-001", "UAC bypass via sdclt.exe on IEWIN7: registry hijack to High-integrity cmd in 9.3 s. COR-001 chain. True positive.", "0E7C86");
card(s, 5.1, 1.5, 4.3, 1.75, "CASE-002", "Meterpreter-style LSASS access plus remote threads from a UNC-path binary. COR-003. True positive; assume credentials exposed.", "D64545");
s.addText("Each case: raw-event timeline, ATT&CK mapping, root cause, impact, closure classification, detection gap.", { x: 0.6, y: 3.6, w: 8.8, h: 0.9, fontSize: 15, color: "0B1F2A", margin: 0, isTextBox: true, valign: "top" });
// 10 Tuning
s = pres.addSlide({ masterName: "LIGHT" }); s.addText("Tuning decisions backed by evidence", { placeholder: "title" });
s.addText([{ text: "DET-003: rejected a services.exe filter; it hid a real PPLdump attack.", options: { bullet: true, breakLine: true } },
  { text: "DET-013: filtered DC machine accounts (6 to 3 events); allow-list real DCs in production.", options: { bullet: true, breakLine: true } },
  { text: "DET-011 + COR-002: 91 injection events become 2 alerts.", options: { bullet: true, breakLine: true } },
  { text: "DET-022: private-range filter hid 3 lab C2 callbacks (10.0.2.18:4443/8181); blind spot recorded.", options: { bullet: true, breakLine: true } },
  { text: "DET-001: 24 benign-positive log clears kept at high; no suppression.", options: { bullet: true } }],
  { x: 0.6, y: 1.5, w: 8.8, h: 3.4, fontSize: 16, color: "0B1F2A", margin: 0, isTextBox: true, paraSpaceAfter: 10, valign: "top" });
// 11 Next
s = pres.addSlide({ masterName: "DARK" }); s.addText("Gaps, limits and next steps", { placeholder: "title" });
s.addText([{ text: "Biggest gaps: DCShadow, Zerologon, PetiPotam, token abuse, WMI event subscriptions, direct mshta.", options: { bullet: true, breakLine: true } },
  { text: "Pilot high/critical rules on live benign logs for 2-4 weeks to measure false positives.", options: { bullet: true, breakLine: true } },
  { text: "Enable Sysmon 10/12/13, Security 4662/5145/4698, PowerShell script-block logging.", options: { bullet: true, breakLine: true } },
  { text: "Limits: attack-only dataset, short captures, custom harness (not a production SIEM).", options: { bullet: true } }],
  { x: 0.6, y: 2.2, w: 8.8, h: 2.8, fontSize: 17, color: "FFFFFF", margin: 0, isTextBox: true, paraSpaceAfter: 12, valign: "top" });
pres.writeFile({ fileName: "presentation/ThreatShield_Final_Presentation.pptx" }).then(() => applyTheme("presentation/ThreatShield_Final_Presentation.pptx", THEME)).then(() => console.log("deck ok"));
