# forensics/chain_of_custody.py
"""
Forensic Evidence & Audit Layer - Chain of Custody Store
Implements:
  - SHA-256 hashing for evidence integrity verification
  - Immutable custody ledger (tamper-evident log)
  - Evidence lifecycle tracking
  - Integrity verification of stored evidence
  
Compliant with NIST SP 800-86 and ISO 27037 guidelines.
"""

import os
import json
import hashlib
import time
import threading
from datetime import datetime


class ChainOfCustody:
    """
    Chain of Custody management with SHA-256 hash integrity.
    Every action performed on evidence is logged immutably
    with cryptographic hash verification.
    """

    def __init__(self, config):
        self.hash_algo = config.get("hash_algorithm", "sha256")
        self.store_dir = config.get("store_dir", "evidence/chain_of_custody")
        self.ledger_path = config.get("immutable_log", "evidence/custody_ledger.json")
        self.enable_timestamps = config.get("enable_timestamping", True)
        self._ledger = []
        self._lock = threading.Lock()

        os.makedirs(self.store_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.ledger_path), exist_ok=True)
        self._load_ledger()

    def _load_ledger(self):
        """Load existing custody ledger."""
        if os.path.exists(self.ledger_path):
            try:
                with open(self.ledger_path, "r") as f:
                    self._ledger = json.load(f)
            except Exception:
                self._ledger = []

    def _save_ledger(self):
        """Persist the custody ledger."""
        with open(self.ledger_path, "w") as f:
            json.dump(self._ledger, f, indent=2)

    def compute_hash(self, file_path):
        """Compute SHA-256 hash of a file."""
        if self.hash_algo == "sha3_256":
            hasher = hashlib.sha3_256()
        else:
            hasher = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            return None

    def compute_data_hash(self, data):
        """Compute SHA-256 hash of raw data (bytes or string)."""
        if self.hash_algo == "sha3_256":
            hasher = hashlib.sha3_256()
        else:
            hasher = hashlib.sha256()

        if isinstance(data, str):
            data = data.encode('utf-8')

        hasher.update(data)
        return hasher.hexdigest()

    def register_evidence(self, evidence_path, alert_id, collector="system",
                          description="", evidence_type="file"):
        """
        Register a piece of evidence in the chain of custody.
        Computes its hash and creates an immutable ledger entry.
        """
        entry_id = f"COC-{int(time.time() * 1000)}-{len(self._ledger):06d}"

        # Compute hash
        if os.path.isfile(evidence_path):
            file_hash = self.compute_hash(evidence_path)
            file_size = os.path.getsize(evidence_path)
        elif os.path.isdir(evidence_path):
            # Hash all files in directory
            file_hash = self._hash_directory(evidence_path)
            file_size = self._dir_size(evidence_path)
        else:
            file_hash = None
            file_size = 0

        entry = {
            "entry_id": entry_id,
            "alert_id": alert_id,
            "evidence_path": evidence_path,
            "evidence_type": evidence_type,
            "description": description,
            "collector": collector,
            "hash_algorithm": self.hash_algo,
            "hash_value": file_hash,
            "file_size": file_size,
            "registered_at": datetime.now().isoformat(),
            "status": "registered",
            "actions": [
                {
                    "action": "registered",
                    "performed_by": collector,
                    "timestamp": datetime.now().isoformat(),
                    "notes": "Initial evidence registration"
                }
            ],
            "verification_history": []
        }

        # Chain entry to previous entry's hash for tamper detection
        if self._ledger:
            prev_entry = self._ledger[-1]
            prev_json = json.dumps(prev_entry, sort_keys=True)
            entry["prev_entry_hash"] = self.compute_data_hash(prev_json)
        else:
            entry["prev_entry_hash"] = "GENESIS"

        with self._lock:
            self._ledger.append(entry)
            self._save_ledger()

        return entry

    def verify_evidence(self, entry_id):
        """
        Verify the integrity of registered evidence.
        Recomputes the hash and compares with the recorded value.
        """
        entry = self._find_entry(entry_id)
        if not entry:
            return {
                "entry_id": entry_id,
                "status": "not_found",
                "integrity": "unknown"
            }

        evidence_path = entry["evidence_path"]
        recorded_hash = entry["hash_value"]

        if not os.path.exists(evidence_path):
            result = {
                "entry_id": entry_id,
                "status": "missing",
                "integrity": "COMPROMISED",
                "reason": "Evidence file/directory no longer exists",
                "verified_at": datetime.now().isoformat()
            }
        elif os.path.isfile(evidence_path):
            current_hash = self.compute_hash(evidence_path)
            result = {
                "entry_id": entry_id,
                "status": "verified",
                "integrity": "INTACT" if current_hash == recorded_hash else "TAMPERED",
                "recorded_hash": recorded_hash,
                "current_hash": current_hash,
                "hash_match": current_hash == recorded_hash,
                "verified_at": datetime.now().isoformat()
            }
        elif os.path.isdir(evidence_path):
            current_hash = self._hash_directory(evidence_path)
            result = {
                "entry_id": entry_id,
                "status": "verified",
                "integrity": "INTACT" if current_hash == recorded_hash else "TAMPERED",
                "recorded_hash": recorded_hash,
                "current_hash": current_hash,
                "hash_match": current_hash == recorded_hash,
                "verified_at": datetime.now().isoformat()
            }
        else:
            result = {
                "entry_id": entry_id,
                "status": "error",
                "integrity": "unknown"
            }

        # Log verification in the entry
        with self._lock:
            for e in self._ledger:
                if e["entry_id"] == entry_id:
                    e["verification_history"].append(result)
                    break
            self._save_ledger()

        return result

    def verify_ledger_integrity(self):
        """
        Verify the entire custody ledger chain integrity.
        Checks that each entry's prev_entry_hash matches
        the actual hash of the previous entry.
        """
        results = {
            "total_entries": len(self._ledger),
            "verified_at": datetime.now().isoformat(),
            "chain_intact": True,
            "broken_links": []
        }

        for i, entry in enumerate(self._ledger):
            if i == 0:
                if entry.get("prev_entry_hash") != "GENESIS":
                    results["chain_intact"] = False
                    results["broken_links"].append({
                        "index": 0,
                        "reason": "Genesis entry has wrong prev_entry_hash"
                    })
                continue

            prev_entry = self._ledger[i - 1]
            prev_json = json.dumps(prev_entry, sort_keys=True)
            expected_hash = self.compute_data_hash(prev_json)

            if entry.get("prev_entry_hash") != expected_hash:
                results["chain_intact"] = False
                results["broken_links"].append({
                    "index": i,
                    "entry_id": entry.get("entry_id"),
                    "expected": expected_hash,
                    "recorded": entry.get("prev_entry_hash"),
                    "reason": "Hash chain broken - possible tampering"
                })

        return results

    def add_custody_action(self, entry_id, action, performed_by, notes=""):
        """Record a custody action (transfer, access, examination, etc.)."""
        with self._lock:
            for entry in self._ledger:
                if entry["entry_id"] == entry_id:
                    entry["actions"].append({
                        "action": action,
                        "performed_by": performed_by,
                        "timestamp": datetime.now().isoformat(),
                        "notes": notes
                    })
                    self._save_ledger()
                    return True
        return False

    def generate_forensic_report(self, alert_id):
        """
        Generate a court-admissible forensic report for an incident.
        Includes full chain of custody, hash verification, and timeline.
        """
        entries = [e for e in self._ledger if e["alert_id"] == alert_id]

        report = {
            "report_title": "DTARF Forensic Investigation Report",
            "report_id": f"DTARF-REPORT-{int(time.time())}",
            "generated_at": datetime.now().isoformat(),
            "framework_version": "1.0.0",
            "compliance": ["NIST SP 800-86", "ISO 27037"],
            "alert_id": alert_id,
            "evidence_count": len(entries),
            "evidence_chain": [],
            "integrity_summary": {
                "total_verified": 0,
                "all_intact": True,
                "tampered_items": []
            },
            "timeline": []
        }

        for entry in entries:
            # Verify each piece of evidence
            verification = self.verify_evidence(entry["entry_id"])

            chain_item = {
                "entry_id": entry["entry_id"],
                "evidence_path": entry["evidence_path"],
                "evidence_type": entry["evidence_type"],
                "hash_algorithm": entry["hash_algorithm"],
                "hash_value": entry["hash_value"],
                "registered_at": entry["registered_at"],
                "collector": entry["collector"],
                "integrity_status": verification["integrity"],
                "custody_actions": entry["actions"]
            }

            report["evidence_chain"].append(chain_item)
            report["integrity_summary"]["total_verified"] += 1

            if verification["integrity"] != "INTACT":
                report["integrity_summary"]["all_intact"] = False
                report["integrity_summary"]["tampered_items"].append(entry["entry_id"])

            # Build timeline
            for action in entry["actions"]:
                report["timeline"].append({
                    "timestamp": action["timestamp"],
                    "entry_id": entry["entry_id"],
                    "action": action["action"],
                    "performed_by": action["performed_by"],
                    "notes": action["notes"]
                })

        # Sort timeline
        report["timeline"].sort(key=lambda x: x["timestamp"])

        # Save report
        report_dir = os.path.join(self.store_dir, "reports")
        os.makedirs(report_dir, exist_ok=True)
        report_file = os.path.join(report_dir, f"report_{alert_id}.json")
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)

        report["report_file"] = report_file
        return report

    def _find_entry(self, entry_id):
        for entry in self._ledger:
            if entry["entry_id"] == entry_id:
                return entry
        return None

    def _hash_directory(self, dir_path):
        """Hash all files in a directory recursively."""
        if self.hash_algo == "sha3_256":
            hasher = hashlib.sha3_256()
        else:
            hasher = hashlib.sha256()

        for root, dirs, files in sorted(os.walk(dir_path)):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "rb") as f:
                        for chunk in iter(lambda: f.read(8192), b""):
                            hasher.update(chunk)
                except Exception:
                    continue

        return hasher.hexdigest()

    def _dir_size(self, dir_path):
        total = 0
        for root, dirs, files in os.walk(dir_path):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except Exception:
                    pass
        return total

    def get_ledger(self, count=100):
        with self._lock:
            return self._ledger[-count:]

    def get_stats(self):
        return {
            "total_entries": len(self._ledger),
            "hash_algorithm": self.hash_algo,
            "store_directory": self.store_dir,
            "ledger_path": self.ledger_path
        }
