"""Mail reporting: instant alerts (actively exploited, critical, supply-chain malware) and a daily digest."""
from __future__ import annotations

import logging
import smtplib
import socket
import ssl
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from html import escape
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from common import (PRIO_EPSS, PRIO_KEV, PRIO_SEVERITY, alert_priority, iso, parse_iso, sev_rank, utcnow)
from config import Settings
from slm import SlmClient
from store import Store

logger = logging.getLogger(__name__)

STRINGS = {
    "de": {
        "malware": "Supply-Chain-Verdacht: bösartige Pakete (OSV-Malware-Advisories)",
        "kev": "Aktiv ausgenutzt (CISA KEV)",
        "severity": "Neue Schwachstellen mit hoher Schwere",
        "epss": "Neue High-Schwachstellen mit hoher Ausnutzungswahrscheinlichkeit (EPSS)",
        "subj_malware": "{n} Malware-Verdacht",
        "subj_kev": "{n} aktiv ausgenutzt (KEV)",
        "subj_severity": "{n} neue kritische/hohe Schwachstellen",
        "subj_epss": "{n} High mit hohem EPSS",
        "container": "Container/Image",
        "scores": "CVSS {cvss} · EPSS {epss}{ransom}",
        "ransom": " · Ransomware-Nutzung bekannt",
        "action_fix": "Maßnahme: {pkg} auf {fix} aktualisieren und Image neu bauen/deployen.",
        "action_nofix": "Maßnahme: Es gibt noch keinen Fix – Exposition prüfen, Mitigation oder Workaround einplanen.",
        "action_malware": "Maßnahme: Paket sofort entfernen/ersetzen, Image neu bauen, im Container verwendete Zugangsdaten rotieren.",
        "ai": "KI-Einschätzung (lokales Modell, ohne Gewähr)",
        "more": "… und {n} weitere (siehe /findings der API bzw. den Tagesbericht).",
        "footer": "Automatisch erzeugt vom SBOM-Scanner. Die KI-Einschätzung ist eine Formulierungshilfe; Schwere und Alarmierung werden regelbasiert entschieden.",
        "digest_subject": "[SBOM] {host}: Tagesbericht – {crit} kritisch, {kev} KEV, {mal} Malware-Verdacht",
        "digest_summary": "Zusammenfassung",
        "digest_counts": "Überwachte Ziele: {targets} · offen: {crit} kritisch, {high} hoch, {med} mittel · davon {kev} aktiv ausgenutzt",
        "digest_changes": "Seit dem letzten Bericht: {new} neu, {resolved} behoben",
        "digest_new": "Neu seit dem letzten Bericht (Auswahl)",
        "digest_top": "Größte offene Risiken",
        "digest_health": "Betriebszustand",
        "digest_fail": "Scan fehlgeschlagen: {target} ({n}× in Folge) – {err}",
        "digest_stale": "Älteste erfolgreiche Prüfung: {target} vor {hours} h",
        "digest_disk": "Speicher: Reports {reports}, SBOM-Archiv {sboms}, Arbeitsverzeichnis {work}, frei auf Datenträger {free}",
        "digest_ok": "Keine Auffälligkeiten im Betrieb.",
        "digest_ai": "Kurzfassung (lokales Modell, ohne Gewähr)",
        "test_subject": "[SBOM] {host}: Testmail",
        "test_body": "Der Mailversand des SBOM-Scanners funktioniert.",
    },
    "en": {
        "malware": "Supply-chain suspicion: malicious packages (OSV malware advisories)",
        "kev": "Actively exploited (CISA KEV)",
        "severity": "New high-severity vulnerabilities",
        "epss": "New High vulnerabilities with high exploit probability (EPSS)",
        "subj_malware": "{n} malware suspect(s)",
        "subj_kev": "{n} actively exploited (KEV)",
        "subj_severity": "{n} new critical/high vulnerabilities",
        "subj_epss": "{n} High with high EPSS",
        "container": "Container/image",
        "scores": "CVSS {cvss} · EPSS {epss}{ransom}",
        "ransom": " · known ransomware use",
        "action_fix": "Action: update {pkg} to {fix} and rebuild/redeploy the image.",
        "action_nofix": "Action: no fix available yet — review exposure and plan a mitigation or workaround.",
        "action_malware": "Action: remove/replace the package immediately, rebuild the image, rotate credentials used inside the container.",
        "ai": "AI assessment (local model, no guarantee)",
        "more": "… and {n} more (see the API's /findings or the daily report).",
        "footer": "Generated automatically by the SBOM scanner. The AI note is a wording aid; severity and alerting are rule-based.",
        "digest_subject": "[SBOM] {host}: daily report – {crit} critical, {kev} KEV, {mal} malware suspects",
        "digest_summary": "Summary",
        "digest_counts": "Monitored targets: {targets} · open: {crit} critical, {high} high, {med} medium · {kev} actively exploited",
        "digest_changes": "Since the last report: {new} new, {resolved} resolved",
        "digest_new": "New since the last report (selection)",
        "digest_top": "Largest open risks",
        "digest_health": "Operations",
        "digest_fail": "Scan failed: {target} ({n}x in a row) – {err}",
        "digest_stale": "Oldest successful check: {target} {hours} h ago",
        "digest_disk": "Storage: reports {reports}, SBOM archive {sboms}, work dir {work}, free on disk {free}",
        "digest_ok": "No operational issues.",
        "digest_ai": "Summary (local model, no guarantee)",
        "test_subject": "[SBOM] {host}: test mail",
        "test_body": "Mail delivery of the SBOM scanner works.",
    },
}


def _s(cfg: Settings, key: str, **kw) -> str:
    table = STRINGS.get(cfg.report_lang, STRINGS["en"])
    return table[key].format(**kw) if kw else table[key]


def host_label(cfg: Settings) -> str:
    return cfg.report_host_label or socket.gethostname()


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ── rendering ─────────────────────────────────────────────────────────────────
# A report is a list of sections: {"title", "items": [{"title","lines","note","link"}], "more": int}

def render(cfg: Settings, heading: str, sections: list[dict], urgent: bool) -> tuple[str, str]:
    ai_label = _s(cfg, "ai")
    text = [heading, "=" * len(heading), ""]
    color = "#b42318" if urgent else "#1d4ed8"
    html = [
        f'<div style="font-family:Segoe UI,Arial,sans-serif;max-width:760px;color:#111">'
        f'<h2 style="margin:0 0 12px;color:{color}">{escape(heading)}</h2>'
    ]
    for sec in sections:
        text += [f"== {sec['title']} ==", ""]
        html.append(f'<h3 style="margin:18px 0 6px;border-bottom:1px solid #ddd;padding-bottom:3px">{escape(sec["title"])}</h3>')
        for it in sec.get("items", []):
            text.append(f"* {it['title']}")
            html.append(f'<div style="margin:8px 0"><b>{escape(it["title"])}</b>')
            for line in it.get("lines", []):
                text.append(f"    {line}")
                html.append(f'<div style="color:#333">{escape(line)}</div>')
            if it.get("link"):
                text.append(f"    {it['link']}")
                html.append(f'<div><a href="{escape(it["link"])}">{escape(it["link"])}</a></div>')
            if it.get("note"):
                text.append(f"    {ai_label}: {it['note']}")
                html.append(f'<div style="color:#555;font-style:italic">{escape(ai_label)}: {escape(it["note"])}</div>')
            html.append("</div>")
            text.append("")
        if sec.get("more"):
            msg = _s(cfg, "more", n=sec["more"])
            text += [msg, ""]
            html.append(f'<div style="color:#555">{escape(msg)}</div>')
    footer = _s(cfg, "footer")
    text += ["-- ", footer]
    html.append(f'<p style="color:#777;font-size:12px;margin-top:24px">{escape(footer)}</p></div>')
    return "\n".join(text), "".join(html)


def _link(f: dict) -> str:
    cve = next((c for c in f.get("cve_ids") or [] if c.startswith("CVE-")), None)
    if cve:
        return f"https://nvd.nist.gov/vuln/detail/{cve}"
    return f"https://osv.dev/vulnerability/{f['vuln_id']}"


def group_findings(rows: list[dict]) -> list[dict]:
    """Merge rows that describe the same advisory (one CVE in several images or several packages of one image).

    The first row of each advisory keeps its position, so a pre-sorted list stays sorted. The merged row carries
    ``targets`` and ``pkgs`` (unique, in order of appearance) in addition to the usual fields.
    """
    groups: dict[str, dict] = {}
    for f in rows:
        g = groups.get(f["vuln_id"])
        if g is None:
            g = groups[f["vuln_id"]] = {**f, "targets": [], "pkgs": []}
        if f["target"] not in g["targets"]:
            g["targets"].append(f["target"])
        key = (f["pkg"], f["version"], tuple(f.get("fix_versions") or []))
        if key not in g["pkgs"]:
            g["pkgs"].append(key)
    return list(groups.values())


_MAX_TARGETS_SHOWN = 4
_MAX_ACTIONS_SHOWN = 3


def finding_item(cfg: Settings, f: dict, note: Optional[str] = None) -> dict:
    epss = f"{f['epss']:.0%}" if f.get("epss") is not None else "n/a"
    cvss = f"{f['cvss']:.1f}" if f.get("cvss") is not None else "n/a"
    targets = f.get("targets") or [f["target"]]
    pkgs = f.get("pkgs") or [(f["pkg"], f["version"], tuple(f.get("fix_versions") or []))]

    shown = targets[:_MAX_TARGETS_SHOWN]
    extra = len(targets) - len(shown)
    container_line = f"{_s(cfg, 'container')}: {', '.join(shown)}" + (f" (+{extra})" if extra > 0 else "")

    lines = [container_line,
             _s(cfg, "scores", cvss=cvss, epss=epss, ransom=_s(cfg, "ransom") if f.get("ransomware") else "")]
    actions = [_s(cfg, "action_fix", pkg=pkg, fix=", ".join(fix[:3])) for pkg, _ver, fix in pkgs if fix]
    if actions:
        lines.extend(actions[:_MAX_ACTIONS_SHOWN])
    else:
        lines.append(_s(cfg, "action_nofix"))

    first_pkg, first_ver, _fix = pkgs[0]
    more_pkgs = f" +{len(pkgs) - 1}" if len(pkgs) > 1 else ""
    return {"title": f"{f['vuln_id']} — {first_pkg} {first_ver}{more_pkgs} ({f['severity']})",
            "lines": lines, "link": _link(f), "note": note}


def malware_item(cfg: Settings, hit: dict, note: Optional[str] = None) -> dict:
    lines = [f"{_s(cfg, 'container')}: {hit['target']}"]
    if hit.get("summary"):
        lines.append(hit["summary"])
    lines.append(_s(cfg, "action_malware"))
    return {"title": f"{hit['osv_id']} — {hit['purl']}", "lines": lines,
            "link": f"https://osv.dev/vulnerability/{hit['osv_id']}", "note": note}


# ── alerts ────────────────────────────────────────────────────────────────────

def build_alert(cfg: Settings, findings: list[tuple[dict, int]], malware: list[dict], slm: SlmClient) -> tuple[str, str, str, bool]:
    """Returns (subject, text, html, urgent)."""
    budget = cfg.slm_max_items
    sections: list[dict] = []
    parts: list[str] = []
    cap = cfg.alert_max_items

    def note_for(kind: str, obj: dict) -> Optional[str]:
        nonlocal budget
        if budget <= 0 or not slm.enabled:
            return None
        budget -= 1
        return slm.explain_malware(obj) if kind == "malware" else slm.explain_finding(obj, obj["target"])

    if malware:
        shown = malware[:cap]
        sections.append({"title": _s(cfg, "malware"), "items": [malware_item(cfg, h, note_for("malware", h)) for h in shown],
                         "more": len(malware) - len(shown)})
        parts.append(_s(cfg, "subj_malware", n=len(malware)))
        cap = max(0, cap - len(shown))

    for prio, key in ((PRIO_KEV, "kev"), (PRIO_SEVERITY, "severity"), (PRIO_EPSS, "epss")):
        raw = [f for f, p in findings if p == prio]
        if not raw:
            continue
        group = group_findings(raw)
        shown = group[:cap]
        sections.append({"title": _s(cfg, key), "items": [finding_item(cfg, f, note_for("finding", f)) for f in shown],
                         "more": len(group) - len(shown)})
        parts.append(_s(cfg, f"subj_{key}", n=len(raw)))
        cap = max(0, cap - len(shown))

    urgent = bool(malware) or any(p == PRIO_KEV for _, p in findings)
    subject = f"[SBOM] {'ALARM' if urgent else 'Warnung' if cfg.report_lang == 'de' else 'Warning'} {host_label(cfg)}: " + ", ".join(parts)
    heading = subject.removeprefix("[SBOM] ")
    text, html = render(cfg, heading, sections, urgent)
    return subject, text, html, urgent


def dispatch_alerts(cfg: Settings, store: Store, slm: SlmClient) -> dict:
    """Send one mail for everything alert-worthy that has not been announced yet."""

    def prio(f: dict) -> int:
        return alert_priority(f, cfg.alert_min_severity, cfg.alert_on_kev, cfg.alert_epss_threshold)

    findings = store.alertable_findings(prio)
    malware = store.unalerted_malware_hits()
    if not findings and not malware:
        return {"sent": False, "reason": "nothing to report"}
    if not cfg.mail_configured:
        if store.kv_get("warned_no_mail") != utcnow().date().isoformat():
            store.kv_set("warned_no_mail", utcnow().date().isoformat())
            logger.warning(f"{len(findings)} finding(s) and {len(malware)} malware hit(s) await alerting, "
                           "but SMTP_HOST/MAIL_FROM/MAIL_TO are not configured")
        return {"sent": False, "reason": "mail not configured"}

    urgent = bool(malware) or any(p == PRIO_KEV for _, p in findings)
    age = store.kv_age("last_alert_sent_at")
    minutes = cfg.alert_urgent_min_interval_minutes if urgent else cfg.alert_min_interval_minutes
    if age is not None and age < timedelta(minutes=minutes):
        return {"sent": False, "reason": "rate-limited"}          # stays pending, the next cycle sends it all in one mail

    subject, text, html, urgent = build_alert(cfg, findings, malware, slm)
    count = len(findings) + len(malware)
    try:
        send_mail(cfg, subject, text, html, urgent)
    except Exception as e:  # noqa: BLE001 - SMTP/network errors must not stop the scheduler
        logger.error(f"alert mail failed: {e}")
        store.log_alert("alert", subject, cfg.mail_to, count, False, str(e))
        return {"sent": False, "reason": f"send failed: {e}"}
    store.mark_alerted([(f["id"], p) for f, p in findings])
    store.mark_malware_alerted([m["id"] for m in malware])
    store.kv_set("last_alert_sent_at", iso())
    store.log_alert("alert", subject, cfg.mail_to, count, True)
    return {"sent": True, "subject": subject, "items": count}


# ── daily digest ──────────────────────────────────────────────────────────────

def build_digest(cfg: Settings, store: Store, slm: SlmClient, disk: Optional[dict] = None) -> tuple[str, str, str]:
    stats = store.stats()
    since = store.kv_get("last_digest_at") or iso(utcnow() - timedelta(hours=24))
    changes = store.findings_changed_since(since)
    open_rows = store.open_findings()
    malware = store.open_malware_hits()
    sev = stats["open_by_severity"]
    sections: list[dict] = []

    summary_lines = [
        _s(cfg, "digest_counts", targets=stats["targets_active"], crit=sev["Critical"], high=sev["High"],
           med=sev["Medium"], kev=stats["open_kev"]),
        _s(cfg, "digest_changes", new=len(changes["new"]), resolved=len(changes["resolved"])),
    ]
    summary_items = [{"title": line, "lines": []} for line in summary_lines]
    ai = slm.summarize_status({
        "targets": stats["targets_active"], "open_critical": sev["Critical"], "open_high": sev["High"],
        "open_actively_exploited": stats["open_kev"], "new_since_last_report": len(changes["new"]),
        "resolved_since_last_report": len(changes["resolved"]), "malware_suspects": len(malware),
    }) if slm.enabled else None
    if ai:
        summary_items.append({"title": _s(cfg, "digest_ai"), "lines": [ai]})
    sections.append({"title": _s(cfg, "digest_summary"), "items": summary_items})

    if malware:
        sections.append({"title": _s(cfg, "malware"), "items": [malware_item(cfg, h) for h in malware[:cfg.alert_max_items]]})

    top = group_findings([r for r in open_rows if r["kev"] or sev_rank(r["severity"]) >= sev_rank("Critical")])[:10]
    if top:
        sections.append({"title": _s(cfg, "digest_top"), "items": [finding_item(cfg, f) for f in top]})

    new_rows = sorted(changes["new"], key=lambda r: (not r["kev"], -sev_rank(r["severity"]), -(r["epss"] or 0)))
    in_top = {r["vuln_id"] for r in top}
    new_rows = group_findings([r for r in new_rows if r["vuln_id"] not in in_top
                               and (r["kev"] or sev_rank(r["severity"]) >= sev_rank("High"))])[:10]
    if new_rows:
        sections.append({"title": _s(cfg, "digest_new"), "items": [finding_item(cfg, f) for f in new_rows]})

    health: list[dict] = []
    targets = store.list_targets(active_only=True)
    for t in targets:
        if t["fail_count"]:
            health.append({"title": _s(cfg, "digest_fail", target=t["target"], n=t["fail_count"], err=(t["last_error"] or "")[:160]), "lines": []})
    oks = [(parse_iso(t["last_ok_at"]), t["target"]) for t in targets if t["last_ok_at"]]
    if oks:
        oldest, name = min(oks, key=lambda x: x[0])
        hours = int((utcnow() - oldest).total_seconds() // 3600)
        if hours > cfg.rescan_hours * 2:
            health.append({"title": _s(cfg, "digest_stale", target=name, hours=hours), "lines": []})
    if disk:
        health.append({"title": _s(cfg, "digest_disk", reports=human_bytes(disk["reports_bytes"]), sboms=human_bytes(disk["sbom_store_bytes"]),
                                   work=human_bytes(disk["work_bytes"]), free=human_bytes(disk["disk_free_bytes"])), "lines": []})
    if not health:
        health.append({"title": _s(cfg, "digest_ok"), "lines": []})
    sections.append({"title": _s(cfg, "digest_health"), "items": health})

    subject = _s(cfg, "digest_subject", host=host_label(cfg), crit=sev["Critical"], kev=stats["open_kev"], mal=len(malware))
    text, html = render(cfg, subject.removeprefix("[SBOM] "), sections, urgent=bool(malware or stats["open_kev"]))
    return subject, text, html


def send_digest(cfg: Settings, store: Store, slm: SlmClient, disk: Optional[dict] = None) -> dict:
    if not cfg.mail_configured:
        return {"sent": False, "reason": "mail not configured"}
    subject, text, html = build_digest(cfg, store, slm, disk)
    try:
        send_mail(cfg, subject, text, html, urgent=False)
    except Exception as e:  # noqa: BLE001
        logger.error(f"digest mail failed: {e}")
        store.log_alert("digest", subject, cfg.mail_to, 0, False, str(e))
        return {"sent": False, "reason": f"send failed: {e}"}
    store.kv_set("last_digest_at", iso())
    store.log_alert("digest", subject, cfg.mail_to, 0, True)
    return {"sent": True, "subject": subject}


def maybe_send_digest(cfg: Settings, store: Store, slm: SlmClient, disk: Optional[dict] = None) -> Optional[dict]:
    if not (cfg.digest_enabled and cfg.mail_configured):
        return None
    try:
        tz = ZoneInfo(cfg.report_tz)
    except ZoneInfoNotFoundError:
        tz = ZoneInfo("UTC")
    local = utcnow().astimezone(tz)
    today = local.date().isoformat()
    if local.hour < cfg.digest_hour or store.kv_get("last_digest_date") == today:
        return None
    result = send_digest(cfg, store, slm, disk)
    if result.get("sent"):
        store.kv_set("last_digest_date", today)
    return result


# ── SMTP ──────────────────────────────────────────────────────────────────────

def send_mail(cfg: Settings, subject: str, text: str, html: str, urgent: bool = False) -> None:
    if not cfg.mail_configured:
        raise RuntimeError("mail not configured (SMTP_HOST, MAIL_FROM, MAIL_TO)")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.mail_from
    msg["To"] = ", ".join(cfg.mail_to)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid()
    msg["Auto-Submitted"] = "auto-generated"
    if urgent:
        msg["X-Priority"] = "1"
        msg["Importance"] = "high"
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")

    context = ssl.create_default_context()
    if cfg.smtp_ssl:
        client: smtplib.SMTP = smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, timeout=30, context=context)
    else:
        client = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=30)
    with client as smtp:
        if not cfg.smtp_ssl:
            smtp.ehlo()
            if cfg.smtp_starttls:
                smtp.starttls(context=context)
                smtp.ehlo()
        if cfg.smtp_user:
            smtp.login(cfg.smtp_user, cfg.smtp_password)
        smtp.send_message(msg)


def send_test_mail(cfg: Settings) -> str:
    subject = _s(cfg, "test_subject", host=host_label(cfg))
    body = _s(cfg, "test_body")
    send_mail(cfg, subject, body, f"<p>{escape(body)}</p>")
    return subject
