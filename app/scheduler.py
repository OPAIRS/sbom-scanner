"""Continuous operation: every tick scans a few due targets, refreshes feeds, sends alerts, cleans up."""
from __future__ import annotations

import asyncio
import functools
import logging
import time
from typing import Optional

import feeds
import inventory
import reporting
import retention
import scanner
from common import iso
from config import Settings
from slm import SlmClient
from store import Store

logger = logging.getLogger(__name__)


class Scheduler:
    def __init__(self, cfg: Settings, store: Store, scan_lock: asyncio.Lock, slm: SlmClient):
        self.cfg = cfg
        self.store = store
        self.scan_lock = scan_lock
        self.slm = slm
        self.state: dict = {
            "running": False, "last_tick_at": None, "last_tick_seconds": None, "last_error": None,
            "current_target": None, "backlog": 0, "last_batch": [],
        }

    # ── helpers (blocking, run in the default executor) ───────────────────────
    def _maintain_db(self) -> Optional[str]:
        """Update Grype's DB every DB_UPDATE_HOURS (or at first start); return the current fingerprint."""
        age = self.store.kv_age("db_updated_at")
        if age is None or age.total_seconds() >= self.cfg.db_update_hours * 3600:
            ok, fp = scanner.update_grype_db(self.cfg)
            if ok:
                self.store.kv_set("db_updated_at", iso())
            if fp:
                self.store.kv_set("db_fp", fp)
            return fp
        return self.store.kv_get("db_fp") or scanner.grype_db_fingerprint()

    def _discover(self) -> dict[str, tuple[str, Optional[str]]]:
        found = inventory.discover(self.cfg)
        candidates: dict[str, tuple[str, Optional[str]]] = {}
        for source, targets in found.items():
            self.store.mark_inventory(source, targets)
            for target, image_id in targets.items():
                candidates[target] = (source, image_id)
        return candidates

    # ── one tick ──────────────────────────────────────────────────────────────
    async def tick(self) -> int:
        """Run one cycle. Returns the number of targets scanned."""
        loop = asyncio.get_running_loop()
        started = time.monotonic()
        scanned = 0
        try:
            db_fp = await loop.run_in_executor(None, self._maintain_db)
            fresh_kev = await loop.run_in_executor(None, feeds.refresh_kev, self.cfg, self.store)
            if fresh_kev:
                logger.info(f"{len(fresh_kev)} CVE(s) newly added to CISA KEV")

            candidates = await loop.run_in_executor(None, self._discover)
            all_due = self.store.pick_due(candidates, db_fp, self.cfg.rescan_hours, limit=10 ** 6)
            due = all_due[:self.cfg.batch_size]
            self.state["backlog"] = len(all_due)
            self.state["last_batch"] = [d["target"] for d in due]

            if due:
                kev_ids = feeds.load_kev_ids(self.store)
                async with self.scan_lock:
                    for item in due:
                        self.state["current_target"] = item["target"]
                        logger.info(f"scheduled scan: {item['target']} ({item['reason']})")
                        outcome = await loop.run_in_executor(None, functools.partial(
                            scanner.scan_target, self.cfg, self.store, item["target"], item["source"], item["image_id"],
                            db_fp=db_fp, kev_ids=kev_ids,
                        ))
                        scanned += 1
                        if outcome.ok:
                            logger.info(
                                f"{item['target']}: {outcome.summary['total_vulnerabilities']} findings, "
                                f"{outcome.summary['new_findings']} new, {outcome.summary['resolved_findings']} resolved"
                                f"{' (SBOM reused)' if outcome.reused_sbom else ''}")
                        else:
                            logger.warning(f"{item['target']}: scan failed — {outcome.error}")
                self.state["current_target"] = None

            await loop.run_in_executor(None, feeds.check_malicious_packages, self.cfg, self.store)
            await loop.run_in_executor(None, reporting.dispatch_alerts, self.cfg, self.store, self.slm)
            disk = await loop.run_in_executor(None, retention.disk_usage, self.cfg)
            await loop.run_in_executor(None, reporting.maybe_send_digest, self.cfg, self.store, self.slm, disk)

            age = self.store.kv_age("last_retention_at")
            if age is None or age.total_seconds() >= 86400:
                await loop.run_in_executor(None, retention.run_retention, self.cfg, self.store)
                self.store.kv_set("last_retention_at", iso())
            self.state["last_error"] = None
        except Exception as e:  # noqa: BLE001 - the loop must survive anything
            logger.exception("scheduler tick failed")
            self.state["last_error"] = f"{type(e).__name__}: {e}"
        finally:
            self.state["last_tick_at"] = iso()
            self.state["last_tick_seconds"] = round(time.monotonic() - started, 1)
        return scanned

    async def run_forever(self) -> None:
        self.state["running"] = True
        logger.info(
            f"scheduler started: batch={self.cfg.batch_size}, tick={self.cfg.tick_seconds}s, "
            f"rescan={self.cfg.rescan_hours}h, db-update={self.cfg.db_update_hours}h, "
            f"mail={'on' if self.cfg.mail_configured else 'off'}, slm={'on' if self.slm.enabled else 'off'}"
        )
        # Stale scratch dirs from a previous crash never survive a restart.
        await asyncio.get_running_loop().run_in_executor(None, retention.cleanup_work, self.cfg, 0)
        try:
            while True:
                scanned = await self.tick()
                # After a productive tick, continue soon (backlog) but keep a pause so the host stays responsive.
                await asyncio.sleep(self.cfg.batch_pause_seconds if scanned else self.cfg.tick_seconds)
        except asyncio.CancelledError:
            self.state["running"] = False
            raise
