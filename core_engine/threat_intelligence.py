# core_engine/threat_intelligence.py
"""
DTARF Core Analytics Engine - Threat Intelligence Engine
Implements:
  - IOC Correlation (IP, Domain, Hash matching)
  - External Feed Integration (AbuseIPDB, OTX, MISP)
  - Context Enrichment (geo, reputation, threat classification)
"""

import os
import json
import time
import hashlib
import threading
import requests
from datetime import datetime
from collections import defaultdict


class IOCDatabase:
    """
    Local IOC (Indicators of Compromise) database.
    Stores malicious IPs, domains, file hashes, URLs.
    """

    def __init__(self, db_path="data/ioc_database.json"):
        self.db_path = db_path
        self._db = {
            "malicious_ips": {},
            "malicious_domains": {},
            "malicious_hashes": {},
            "malicious_urls": {},
            "last_updated": None
        }
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r") as f:
                    self._db = json.load(f)
            except Exception:
                pass

    def save(self):
        with self._lock:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            self._db["last_updated"] = datetime.now().isoformat()
            with open(self.db_path, "w") as f:
                json.dump(self._db, f, indent=2)

    def add_ioc(self, ioc_type, indicator, metadata=None):
        """Add an IOC to the database."""
        with self._lock:
            section = f"malicious_{ioc_type}"
            if section in self._db:
                self._db[section][indicator] = {
                    "added": datetime.now().isoformat(),
                    "source": (metadata or {}).get("source", "manual"),
                    "confidence": (metadata or {}).get("confidence", 50),
                    "tags": (metadata or {}).get("tags", []),
                    "description": (metadata or {}).get("description", "")
                }

    def check_ip(self, ip):
        """Check if an IP is in the malicious IOC database."""
        with self._lock:
            entry = self._db["malicious_ips"].get(ip)
            if entry:
                return {"match": True, "indicator": ip, "type": "ip", **entry}
        return {"match": False}

    def check_domain(self, domain):
        with self._lock:
            entry = self._db["malicious_domains"].get(domain)
            if entry:
                return {"match": True, "indicator": domain, "type": "domain", **entry}
        return {"match": False}

    def check_hash(self, file_hash):
        with self._lock:
            entry = self._db["malicious_hashes"].get(file_hash)
            if entry:
                return {"match": True, "indicator": file_hash, "type": "hash", **entry}
        return {"match": False}

    def get_stats(self):
        with self._lock:
            return {
                "malicious_ips": len(self._db["malicious_ips"]),
                "malicious_domains": len(self._db["malicious_domains"]),
                "malicious_hashes": len(self._db["malicious_hashes"]),
                "malicious_urls": len(self._db["malicious_urls"]),
                "last_updated": self._db.get("last_updated")
            }


class AbuseIPDBClient:
    """Client for AbuseIPDB threat intelligence feed."""

    API_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, config):
        self.api_key = config.get("api_key") or os.environ.get("ABUSEIPDB_API_KEY", "")
        self.enabled = config.get("enabled", True) and bool(self.api_key)
        self.confidence_threshold = config.get("confidence_threshold", 80)
        self.cache_ttl = config.get("cache_ttl_sec", 3600)
        self._cache = {}
        self._lock = threading.Lock()

    def check_ip(self, ip):
        """Check an IP against AbuseIPDB."""
        if not self.enabled:
            return None

        # Check cache
        with self._lock:
            cached = self._cache.get(ip)
            if cached and time.time() - cached["cached_at"] < self.cache_ttl:
                return cached["result"]

        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True
            }
            resp = requests.get(
                f"{self.API_URL}/check",
                headers=headers,
                params=params,
                timeout=10
            )

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                result = {
                    "source": "abuseipdb",
                    "ip": ip,
                    "abuse_confidence": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "domain": data.get("domain", ""),
                    "is_tor": data.get("isTor", False),
                    "is_malicious": data.get("abuseConfidenceScore", 0) >= self.confidence_threshold,
                    "categories": data.get("reports", [])[:5]
                }

                with self._lock:
                    self._cache[ip] = {"result": result, "cached_at": time.time()}

                return result

        except Exception:
            pass

        return None


class OTXClient:
    """Client for AlienVault OTX threat intelligence feed."""

    API_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, config):
        self.api_key = config.get("api_key") or os.environ.get("OTX_API_KEY", "")
        self.enabled = config.get("enabled", True) and bool(self.api_key)
        self.cache_ttl = config.get("cache_ttl_sec", 3600)
        self._cache = {}
        self._lock = threading.Lock()

    def check_ip(self, ip):
        """Check an IP against OTX."""
        if not self.enabled:
            return None

        with self._lock:
            cached = self._cache.get(ip)
            if cached and time.time() - cached["cached_at"] < self.cache_ttl:
                return cached["result"]

        try:
            headers = {"X-OTX-API-KEY": self.api_key}
            resp = requests.get(
                f"{self.API_URL}/indicators/IPv4/{ip}/general",
                headers=headers,
                timeout=10
            )

            if resp.status_code == 200:
                data = resp.json()
                pulses = data.get("pulse_info", {}).get("count", 0)
                result = {
                    "source": "otx",
                    "ip": ip,
                    "pulse_count": pulses,
                    "reputation": data.get("reputation", 0),
                    "country": data.get("country_name", ""),
                    "is_malicious": pulses > 0,
                    "tags": [p.get("name", "") for p in
                             data.get("pulse_info", {}).get("pulses", [])[:5]]
                }

                with self._lock:
                    self._cache[ip] = {"result": result, "cached_at": time.time()}

                return result

        except Exception:
            pass

        return None

    def check_domain(self, domain):
        """Check a domain against OTX."""
        if not self.enabled:
            return None

        try:
            headers = {"X-OTX-API-KEY": self.api_key}
            resp = requests.get(
                f"{self.API_URL}/indicators/domain/{domain}/general",
                headers=headers,
                timeout=10
            )

            if resp.status_code == 200:
                data = resp.json()
                pulses = data.get("pulse_info", {}).get("count", 0)
                return {
                    "source": "otx",
                    "domain": domain,
                    "pulse_count": pulses,
                    "is_malicious": pulses > 0,
                    "alexa_rank": data.get("alexa", ""),
                    "whois": data.get("whois", "")[:200] if data.get("whois") else ""
                }

        except Exception:
            pass

        return None


class MISPClient:
    """Client for MISP (Malware Information Sharing Platform) integration."""

    def __init__(self, config):
        self.url = config.get("url", "")
        self.api_key = config.get("api_key", os.environ.get("MISP_API_KEY", ""))
        self.enabled = config.get("enabled", False) and bool(self.api_key) and bool(self.url)
        self.verify_cert = config.get("verify_cert", True)

    def check_indicator(self, value):
        """Search for an indicator in MISP."""
        if not self.enabled:
            return None

        try:
            headers = {
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            body = {
                "value": value,
                "limit": 5
            }
            resp = requests.post(
                f"{self.url.rstrip('/')}/attributes/restSearch",
                headers=headers,
                json=body,
                verify=self.verify_cert,
                timeout=10
            )

            if resp.status_code == 200:
                data = resp.json().get("response", {}).get("Attribute", [])
                if data:
                    events = []
                    for attr in data:
                        event = attr.get("Event", {})
                        events.append({
                            "event_id": event.get("id"),
                            "info": event.get("info"),
                            "threat_level": event.get("threat_level_id"),
                            "org": event.get("Orgc", {}).get("name")
                        })
                    
                    return {
                        "source": "misp",
                        "indicator": value,
                        "is_malicious": True,
                        "matches": len(data),
                        "events": events
                    }
        except Exception as e:
            # print(f"MISP error: {e}")
            pass

        return None


class ThreatIntelligenceEngine:
    """
    Unified Threat Intelligence Engine.
    Correlates IOCs with local database and external TI feeds.
    Provides context enrichment for alerts.
    """

    def __init__(self, config):
        ti_config = config.get("threat_intelligence", {})
        self.enabled = ti_config.get("enabled", True)

        # Initialize components
        self.ioc_db = IOCDatabase(ti_config.get("local_ioc_db", "data/ioc_database.json"))

        feeds = ti_config.get("feeds", {})
        self.abuseipdb = AbuseIPDBClient(feeds.get("abuseipdb", {}))
        self.otx = OTXClient(feeds.get("otx", {}))
        self.misp = MISPClient(feeds.get("misp", {}))

        self._correlation_cache = {}
        self._alerts = []
        self._lock = threading.Lock()

    def correlate_ip(self, ip):
        """
        Correlate an IP address against all intelligence sources.
        Returns enriched context.
        """
        if not self.enabled:
            return {"ip": ip, "is_malicious": False, "sources": []}

        results = {
            "ip": ip,
            "is_malicious": False,
            "confidence": 0,
            "sources": [],
            "tags": [],
            "enrichment": {},
            "checked_at": datetime.now().isoformat()
        }

        # 1. Check local IOC database
        local = self.ioc_db.check_ip(ip)
        if local["match"]:
            results["is_malicious"] = True
            results["confidence"] = max(results["confidence"], local.get("confidence", 80))
            results["sources"].append({"source": "local_ioc", **local})

        # 2. Check AbuseIPDB
        abuse = self.abuseipdb.check_ip(ip)
        if abuse:
            results["sources"].append(abuse)
            if abuse.get("is_malicious"):
                results["is_malicious"] = True
                results["confidence"] = max(results["confidence"],
                                            abuse.get("abuse_confidence", 0))
            results["enrichment"]["country"] = abuse.get("country", "")
            results["enrichment"]["isp"] = abuse.get("isp", "")
            results["enrichment"]["is_tor"] = abuse.get("is_tor", False)

        # 3. Check OTX
        otx = self.otx.check_ip(ip)
        if otx:
            results["sources"].append(otx)
            if otx.get("is_malicious"):
                results["is_malicious"] = True
                results["confidence"] = max(results["confidence"], 70)
            results["tags"].extend(otx.get("tags", []))

        # 4. Check MISP
        misp = self.misp.check_indicator(ip)
        if misp:
            results["sources"].append(misp)
            results["is_malicious"] = True
            results["confidence"] = max(results["confidence"], 85)

        # Generate alert if malicious
        if results["is_malicious"]:
            alert = {
                "type": "malicious_ip_detected",
                "severity": min(95, results["confidence"]),
                "ip": ip,
                "confidence": results["confidence"],
                "sources": [s.get("source", "") for s in results["sources"]],
                "timestamp": datetime.now().isoformat()
            }
            with self._lock:
                self._alerts.append(alert)

        return results

    def correlate_domain(self, domain):
        """Correlate a domain against intelligence sources."""
        if not self.enabled:
            return {"domain": domain, "is_malicious": False}

        results = {
            "domain": domain,
            "is_malicious": False,
            "sources": [],
            "checked_at": datetime.now().isoformat()
        }

        local = self.ioc_db.check_domain(domain)
        if local["match"]:
            results["is_malicious"] = True
            results["sources"].append({"source": "local_ioc", **local})

        otx = self.otx.check_domain(domain)
        if otx:
            results["sources"].append(otx)
            if otx.get("is_malicious"):
                results["is_malicious"] = True

        misp = self.misp.check_indicator(domain)
        if misp:
            results["sources"].append(misp)
            results["is_malicious"] = True

        return results

    def correlate_hash(self, file_hash):
        """Check a file hash against IOC database and MISP."""
        local = self.ioc_db.check_hash(file_hash)
        if local["match"]:
            return local
        
        misp = self.misp.check_indicator(file_hash)
        if misp:
            return {"match": True, "source": "misp", **misp}
            
        return {"match": False}

    def enrich_alert(self, alert):
        """Enrich an existing alert with threat intelligence context."""
        enriched = dict(alert)
        enriched["ti_enrichment"] = {}

        # Try to enrich based on source IP
        src_ip = alert.get("src_ip") or alert.get("ip") or alert.get("source")
        if src_ip and isinstance(src_ip, str) and "." in src_ip:
            ip_intel = self.correlate_ip(src_ip)
            enriched["ti_enrichment"]["source_ip"] = ip_intel

        return enriched

    def get_alerts(self, count=100):
        with self._lock:
            return list(self._alerts[-count:])

    def get_stats(self):
        return {
            "ioc_database": self.ioc_db.get_stats(),
            "abuseipdb_enabled": self.abuseipdb.enabled,
            "otx_enabled": self.otx.enabled,
            "misp_enabled": self.misp.enabled,
            "total_ti_alerts": len(self._alerts)
        }

    def add_ioc(self, ioc_type, indicator, metadata=None):
        """Manually add an IOC to the local database."""
        self.ioc_db.add_ioc(ioc_type, indicator, metadata)
        self.ioc_db.save()
