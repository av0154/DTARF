# dashboard/app.py
"""
DTARF Dashboard - Flask Web Application
SIEM-style monitoring dashboard with:
  - Real-time alert feed
  - System telemetry visualization
  - Threat intelligence status
  - Forensic evidence browser
  - Performance metrics
  - Response action history
"""

import os
import json
import time
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory, make_response
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity
)


def create_app(dtarf_engine=None, config=None):
    """Create and configure the Flask dashboard application."""

    app = Flask(__name__, static_folder='static', static_url_path='/static')

    dash_config = config or {}
    app.config['SECRET_KEY'] = dash_config.get('secret_key', 'dtarf-secret-key')
    app.config['JWT_SECRET_KEY'] = dash_config.get('jwt_secret', 'dtarf-jwt-secret')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False

    CORS(app, origins=dash_config.get('cors_origins', ['*']))
    jwt = JWTManager(app)

    # Default users (in production, use a proper user store)
    USERS = {
        "admin": {"password": "admin123", "role": "admin"},
        "analyst": {"password": "analyst123", "role": "analyst"},
        "viewer": {"password": "viewer123", "role": "viewer"}
    }

    engine = dtarf_engine

    # =====================
    # Authentication Routes
    # =====================

    @app.route('/api/auth/login', methods=['POST'])
    def login():
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')

        user = USERS.get(username)
        if user and user['password'] == password:
            token = create_access_token(
                identity=username,
                additional_claims={"role": user["role"]}
            )
            return jsonify({
                "token": token,
                "username": username,
                "role": user["role"]
            })
        return jsonify({"error": "Invalid credentials"}), 401

    # =====================
    # Dashboard API Routes
    # =====================

    @app.route('/api/dashboard/summary', methods=['GET'])
    @jwt_required()
    def dashboard_summary():
        """Get dashboard summary with all key metrics."""
        if not engine:
            return jsonify({"error": "Engine not initialized"}), 500

        summary = {
            "timestamp": datetime.now().isoformat(),
            "alerts": engine.get_alert_summary(),
            "system": engine.get_system_summary(),
            "performance": engine.get_performance_summary(),
            "threat_intel": engine.get_ti_summary(),
            "forensics": engine.get_forensics_summary()
        }
        return jsonify(summary)

    # =====================
    # Alert Routes
    # =====================

    @app.route('/api/alerts', methods=['GET'])
    @jwt_required()
    def get_alerts():
        status = request.args.get('status')
        count = int(request.args.get('count', 100))
        alerts = engine.orchestrator.get_alerts(status=status, count=count) if engine else []
        return jsonify({"alerts": alerts, "total": len(alerts)})

    @app.route('/api/alerts/<alert_id>', methods=['GET'])
    @jwt_required()
    def get_alert_detail(alert_id):
        if engine:
            for a in engine.orchestrator._processed:
                if a.id == alert_id:
                    return jsonify(a.to_dict())
        return jsonify({"error": "Alert not found"}), 404

    @app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
    @jwt_required()
    def acknowledge_alert(alert_id):
        if engine:
            engine.orchestrator.update_alert_status(alert_id, "acknowledged")
            return jsonify({"status": "acknowledged", "alert_id": alert_id})
        return jsonify({"error": "Engine not found"}), 404

    @app.route('/api/alerts/<alert_id>/false-positive', methods=['POST'])
    @jwt_required()
    def mark_false_positive(alert_id):
        if engine:
            engine.orchestrator.update_alert_status(alert_id, "false_positive")
            engine.metrics.mark_false_positive(alert_id)
            return jsonify({"status": "false_positive", "alert_id": alert_id})
        return jsonify({"error": "Alert not found"}), 404

    # =====================
    # Telemetry Routes
    # =====================

    @app.route('/api/telemetry/current', methods=['GET'])
    @jwt_required()
    def get_current_telemetry():
        if engine and engine.telemetry:
            latest = engine.telemetry.get_latest()
            if latest:
                return jsonify(latest.to_dict())
        return jsonify({})

    @app.route('/api/telemetry/history', methods=['GET'])
    @jwt_required()
    def get_telemetry_history():
        count = int(request.args.get('count', 100))
        if engine and engine.telemetry:
            history = engine.telemetry.get_history(count)
            return jsonify({"history": [s.to_dict() for s in history]})
        return jsonify({"history": []})

    # =====================
    # Threat Intelligence Routes
    # =====================

    @app.route('/api/ti/check-ip', methods=['POST'])
    @jwt_required()
    def check_ip():
        data = request.get_json()
        ip = data.get('ip', '')
        if engine and ip:
            result = engine.ti_engine.correlate_ip(ip)
            return jsonify(result)
        return jsonify({"error": "IP required"}), 400

    @app.route('/api/ti/check-domain', methods=['POST'])
    @jwt_required()
    def check_domain():
        data = request.get_json()
        domain = data.get('domain', '')
        if engine and domain:
            result = engine.ti_engine.correlate_domain(domain)
            return jsonify(result)
        return jsonify({"error": "Domain required"}), 400

    @app.route('/api/ti/ioc', methods=['POST'])
    @jwt_required()
    def add_ioc():
        data = request.get_json()
        ioc_type = data.get('type', '')
        indicator = data.get('indicator', '')
        if engine and ioc_type and indicator:
            engine.ti_engine.add_ioc(ioc_type, indicator, data.get('metadata'))
            return jsonify({"status": "added"})
        return jsonify({"error": "Type and indicator required"}), 400

    @app.route('/api/ti/stats', methods=['GET'])
    @jwt_required()
    def get_ti_stats():
        if engine:
            return jsonify(engine.ti_engine.get_stats())
        return jsonify({})

    # =====================
    # Response Routes
    # =====================

    @app.route('/api/response/blacklist', methods=['GET'])
    @jwt_required()
    def get_blacklist():
        if engine:
            return jsonify(engine.action_executor.get_blacklist())
        return jsonify({})

    @app.route('/api/response/blacklist/<ip>', methods=['DELETE'])
    @jwt_required()
    def remove_from_blacklist(ip):
        if engine:
            result = engine.action_executor.remove_blacklist(ip)
            return jsonify(result)
        return jsonify({"error": "Engine not available"}), 500

    @app.route('/api/response/action-log', methods=['GET'])
    @jwt_required()
    def get_action_log():
        count = int(request.args.get('count', 100))
        if engine:
            return jsonify({"actions": engine.action_executor.get_action_log(count)})
        return jsonify({"actions": []})

    @app.route('/api/response/stats', methods=['GET'])
    @jwt_required()
    def get_response_stats():
        if engine:
            return jsonify(engine.orchestrator.get_stats())
        return jsonify({})

    # =====================
    # Forensics Routes
    # =====================

    @app.route('/api/forensics/ledger', methods=['GET'])
    @jwt_required()
    def get_custody_ledger():
        count = int(request.args.get('count', 100))
        if engine:
            return jsonify({"entries": engine.custody.get_ledger(count)})
        return jsonify({"entries": []})

    @app.route('/api/forensics/verify/<entry_id>', methods=['POST'])
    @jwt_required()
    def verify_evidence(entry_id):
        if engine:
            result = engine.custody.verify_evidence(entry_id)
            return jsonify(result)
        return jsonify({"error": "Engine not available"}), 500

    @app.route('/api/forensics/verify-ledger', methods=['POST'])
    @jwt_required()
    def verify_ledger():
        if engine:
            result = engine.custody.verify_ledger_integrity()
            return jsonify(result)
        return jsonify({"error": "Engine not available"}), 500

    @app.route('/api/forensics/report/<alert_id>', methods=['POST'])
    @jwt_required()
    def generate_report(alert_id):
        if engine:
            report = engine.custody.generate_forensic_report(alert_id)
            return jsonify(report)
        return jsonify({"error": "Engine not available"}), 500

    @app.route('/api/forensics/stats', methods=['GET'])
    @jwt_required()
    def get_forensics_stats():
        if engine:
            return jsonify(engine.custody.get_stats())
        return jsonify({})

    # =====================
    # Performance Routes
    # =====================

    @app.route('/api/performance/metrics', methods=['GET'])
    @jwt_required()
    def get_performance_metrics():
        if engine:
            return jsonify(engine.metrics.get_metrics())
        return jsonify({})

    @app.route('/api/performance/comparison', methods=['GET'])
    @jwt_required()
    def get_baseline_comparison():
        if engine:
            return jsonify(engine.metrics.get_baseline_comparison())
        return jsonify({})

    # =====================
    # Network Stats Routes
    # =====================

    @app.route('/api/network/stats', methods=['GET'])
    @jwt_required()
    def get_network_stats():
        if engine and engine.sniffer:
            return jsonify({
                "sniffer_stats": engine.sniffer.get_stats(),
                "window_stats": engine.sniffer.get_window_stats()
            })
        return jsonify({})

    # =====================
    # Detection Engine Routes
    # =====================

    @app.route('/api/detection/alerts', methods=['GET'])
    @jwt_required()
    def get_detection_alerts():
        count = int(request.args.get('count', 100))
        if engine:
            return jsonify({"alerts": engine.detection.get_alerts(count)})
        return jsonify({"alerts": []})

    @app.route('/api/detection/stats', methods=['GET'])
    @jwt_required()
    def get_detection_stats():
        if engine:
            return jsonify(engine.detection.get_stats())
        return jsonify({})

    # =====================
    # Health & Status
    # =====================

    @app.route('/api/health', methods=['GET'])
    def health():
        return jsonify({
            "status": "healthy",
            "framework": "DTARF",
            "version": "1.0.0",
            "timestamp": datetime.now().isoformat(),
            "engine_active": engine is not None
        })

    # =====================
    # Serve Frontend
    # =====================

    @app.route('/')
    def serve_index():
        return send_from_directory(app.static_folder, 'index.html')

    @app.route('/<path:path>')
    def serve_static(path):
        if os.path.exists(os.path.join(app.static_folder, path)):
            return send_from_directory(app.static_folder, path)
        return send_from_directory(app.static_folder, 'index.html')

    return app
