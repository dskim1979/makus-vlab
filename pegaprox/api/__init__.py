# -*- coding: utf-8 -*-
"""
PegaProx API Blueprint Registration
"""
import logging


def register_blueprints(app):
    """Register all API blueprints with the Flask app."""
    from pegaprox.api.auth import bp as auth_bp
    from pegaprox.api.users import bp as users_bp
    from pegaprox.api.clusters import bp as clusters_bp
    from pegaprox.api.vms import bp as vms_bp
    from pegaprox.api.nodes import bp as nodes_bp
    from pegaprox.api.pbs import bp as pbs_bp
    from pegaprox.api.storage import bp as storage_bp
    from pegaprox.api.datacenter import bp as datacenter_bp
    from pegaprox.api.vmware import bp as vmware_bp
    from pegaprox.api.schedules import bp as schedules_bp
    from pegaprox.api.reports import bp as reports_bp
    from pegaprox.api.settings import bp as settings_bp
    from pegaprox.api.alerts import bp as alerts_bp
    from pegaprox.api.realtime import bp as realtime_bp
    from pegaprox.api.search import bp as search_bp
    from pegaprox.api.static_files import bp as static_files_bp
    from pegaprox.api.history import bp as history_bp
    from pegaprox.api.groups import bp as groups_bp
    from pegaprox.api.ceph import bp as ceph_bp
    from pegaprox.api.xhm import bp as xhm_bp
    from pegaprox.api.site_recovery import bp as site_recovery_bp
    from pegaprox.api.plugins import bp as plugins_bp
    from pegaprox.api.webauthn import bp as webauthn_bp
    from pegaprox.api.metrics_exporter import bp as metrics_exporter_bp
    from pegaprox.api.insights import bp as insights_bp
    from pegaprox.api.templates_lib import bp as templates_lib_bp
    from pegaprox.api.oci_catalog import bp as oci_catalog_bp
    from pegaprox.api.push import bp as push_bp, register_alert_handler
    from pegaprox.api.costs import bp as costs_bp
    from pegaprox.api.drift import bp as drift_bp, start_scanner as start_drift_scanner
    from pegaprox.api.audit_search import bp as audit_search_bp
    from pegaprox.api.siem import bp as siem_bp, start_worker as start_siem_worker
    from pegaprox.api.snapshots import bp as snapshots_bp, start_scheduler as start_snap_scheduler
    from pegaprox.api.topology import bp as topology_bp
    from pegaprox.api.power import bp as power_bp
    from pegaprox.api.gpu import bp as gpu_bp
    from pegaprox.api.korean_reports import bp as korean_reports_bp  # 한국형 보고서 (MOAVI Desk 이식)
    from pegaprox.api.dr_drill import bp as dr_drill_bp
    from pegaprox.api.multi_sdn import bp as multi_sdn_bp, start_scanner as start_multi_sdn_scanner
    from pegaprox.api.auto_install import bp as auto_install_bp
    from pegaprox.api.ha import bp as ha_bp
    from pegaprox.api.banners import bp as banners_bp
    from pegaprox.api.directory_verify import bp as directory_verify_bp  # MAKUS: 앞단(MOAVI Desk 화면)의 LDAP 확인
    from pegaprox.api.frontend_branding import bp as frontend_branding_bp  # MAKUS: 앞단(MOAVI Desk 화면)의 화이트라벨
    from pegaprox.api.frontend_audit import bp as frontend_audit_bp  # MAKUS: 앞단(MOAVI Desk 화면)의 감사 기록
    from pegaprox.api.frontend_ai import bp as frontend_ai_bp  # MAKUS: 앞단(MOAVI Desk 화면)의 AI 도우미 설정
    from pegaprox.api.flows import bp as flows_bp  # MAKUS: sFlow 네트워크 흐름
    from pegaprox.api.microseg import bp as microseg_bp  # MAKUS: 마이크로 세그멘테이션
    from pegaprox.api.vlab import bp as vlab_bp  # MOAVI Desk: 데스크톱·자원 할당 (vLAB 콘솔용)
    from pegaprox.api.vlab_support import bp as vlab_support_bp  # MOAVI Desk: 서포트 번들 (기간 지정)
    from pegaprox.api.vlab_accel import bp as vlab_accel_bp  # MOAVI Desk: 가속 카드 · 패스스루 점검
    from pegaprox.api.vlab_env import bp as vlab_env_bp  # MOAVI Desk: 환경 카탈로그 · NVIDIA MIG
    from pegaprox.api.vlab_desktpl import bp as vlab_desktpl_bp  # MOAVI Desk: 데스크톱 템플릿 (일반 · 연구원 · GPU · NPU · FPGA)
    from pegaprox.api.vlab_enroll import bp as vlab_enroll_bp  # MOAVI Desk: LAB 단말 대량 등록 (등록 코드)
    from pegaprox.api.vlab_reserve import bp as vlab_reserve_bp  # MOAVI Desk: LAB 예약
    from pegaprox.api.vlab_license import bp as vlab_license_bp  # MOAVI Desk: 라이선스 사용량 · 보고서
    from pegaprox.api.vlab_data import bp as vlab_data_bp  # MOAVI Desk: 연구 데이터 (데이터셋, 파일 전송, 반출 통제)
    from pegaprox.api.vlab_accounts import bp as vlab_accounts_bp  # MOAVI Desk: 비밀번호 찾기·메일 인증·일괄 등록·사용 기한·약관
    from pegaprox.api.vlab_work import bp as vlab_work_bp  # MOAVI Desk: 장시간 작업 보호 · GPU/NPU 사용률 · 유휴 카드 회수
    from pegaprox.api.vlab_research import bp as vlab_research_bp  # MOAVI Desk: GPU 작업 큐 · 할당량 · GPU-시간 · 웹 IDE
    from pegaprox.api.vlab_notices import bp as vlab_notices_bp  # MOAVI Desk: 개인 알림 (메일 받을 항목)
    from pegaprox.api.vlab_features import bp as vlab_features_bp  # MOAVI Desk: 사이트 프로필 · 기능 묶음
    from pegaprox.api.vlab_ops_notices import bp as vlab_ops_notices_bp  # MOAVI Desk: 운영 알림(관리자)
    from pegaprox.api.vlab_builds import bp as vlab_builds_bp  # MOAVI Desk: 빌드 결과물 · CI 연동
    from pegaprox.api.vlab_accel_book import bp as vlab_accel_book_bp  # MOAVI Desk: 카드 · 보드 예약
    from pegaprox.api.vlab_forecast import bp as vlab_forecast_bp  # MOAVI Desk: 증설 예측
    from pegaprox.api.vlab_next import bp as vlab_next_bp  # MOAVI Desk: 부서·가입 심사·USB·게이트웨이·골든 이미지·보드 LAB·빌드 팜·라이선스 서버

    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(clusters_bp)
    app.register_blueprint(vms_bp)
    app.register_blueprint(nodes_bp)
    app.register_blueprint(pbs_bp)
    app.register_blueprint(storage_bp)
    app.register_blueprint(datacenter_bp)
    app.register_blueprint(vmware_bp)
    app.register_blueprint(schedules_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(realtime_bp)
    app.register_blueprint(search_bp)
    app.register_blueprint(static_files_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(groups_bp)
    app.register_blueprint(ceph_bp)
    app.register_blueprint(xhm_bp)
    app.register_blueprint(site_recovery_bp)
    app.register_blueprint(plugins_bp)
    app.register_blueprint(webauthn_bp)
    app.register_blueprint(metrics_exporter_bp)
    app.register_blueprint(insights_bp)
    app.register_blueprint(templates_lib_bp)
    app.register_blueprint(oci_catalog_bp)
    app.register_blueprint(push_bp)
    app.register_blueprint(costs_bp)
    app.register_blueprint(drift_bp)
    app.register_blueprint(audit_search_bp)
    app.register_blueprint(siem_bp)
    app.register_blueprint(snapshots_bp)
    app.register_blueprint(topology_bp)
    app.register_blueprint(power_bp)
    app.register_blueprint(gpu_bp)
    app.register_blueprint(korean_reports_bp)
    app.register_blueprint(dr_drill_bp)
    app.register_blueprint(multi_sdn_bp)
    app.register_blueprint(auto_install_bp)
    app.register_blueprint(ha_bp)
    app.register_blueprint(banners_bp)
    app.register_blueprint(directory_verify_bp)
    app.register_blueprint(frontend_branding_bp)
    app.register_blueprint(frontend_audit_bp)
    app.register_blueprint(frontend_ai_bp)
    app.register_blueprint(flows_bp)
    app.register_blueprint(microseg_bp)
    app.register_blueprint(vlab_bp)
    app.register_blueprint(vlab_next_bp)
    app.register_blueprint(vlab_support_bp)
    app.register_blueprint(vlab_accel_bp)
    app.register_blueprint(vlab_env_bp)
    app.register_blueprint(vlab_desktpl_bp)
    app.register_blueprint(vlab_enroll_bp)
    app.register_blueprint(vlab_reserve_bp)
    app.register_blueprint(vlab_license_bp)
    app.register_blueprint(vlab_data_bp)
    app.register_blueprint(vlab_accounts_bp)
    app.register_blueprint(vlab_work_bp)
    app.register_blueprint(vlab_research_bp)
    app.register_blueprint(vlab_notices_bp)
    app.register_blueprint(vlab_features_bp)
    app.register_blueprint(vlab_ops_notices_bp)
    app.register_blueprint(vlab_builds_bp)
    app.register_blueprint(vlab_accel_book_bp)
    app.register_blueprint(vlab_forecast_bp)
    from pegaprox.api.vlab_accounts import attach_terms_gate
    attach_terms_gate(app)   # after every vlab blueprint is registered

    # Initialize WebSocket support for realtime blueprint
    from pegaprox.api.realtime import sock
    sock.init_app(app)

    # MK May 2026 — wire push handler into the alerts pipeline
    try:
        register_alert_handler()
    except Exception:
        pass

    # NS May 2026 — drift scanner thread (6h cadence; harmless if mgrs not yet up)
    try:
        start_drift_scanner()
    except Exception as e:
        logging.warning(f"drift scanner start failed: {e}")

    # MK Jul 2026 — #612 Phase 2: cross-cluster EVPN drift scanner (6h cadence,
    # detect-only unless multi_sdn_drift_reconcile is opted in)
    try:
        start_multi_sdn_scanner()
    except Exception as e:
        logging.warning(f"multi_sdn scanner start failed: {e}")

    # MK May 2026 — SIEM forwarder worker
    try:
        start_siem_worker()
    except Exception as e:
        logging.warning(f"siem worker start failed: {e}")

    # NS May 2026 — snapshot scheduler (60s tick, idempotent)
    try:
        start_snap_scheduler()
    except Exception as e:
        logging.warning(f"snapshot scheduler start failed: {e}")
