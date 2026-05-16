from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from pkica.services.audit_service import event_values, list_events
from pkica.services.certificate_service import (
    get_certificate,
    issue_certificate_from_csr,
    issue_certificate_from_request,
    list_certificates,
    revoke_certificate,
    verify_certificate_path,
    verify_certificate_pem,
)
from pkica.services.crl_service import crl_info, publish_crl
from pkica.services.request_service import (
    ALLOWED_PROFILES,
    approve_request,
    get_request,
    list_requests,
    profile_validation,
    reject_request,
    submit_csr_pem,
)
from pkica.services.status_service import cert_info, get_status
from pkica.pki.crl import REASON_MAP
from pkica.config import BASE_DIR, INTERMEDIATE_CERT_PATH, ROOT_CERT_PATH

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")


def format_datetime(value: object, fallback: str = "-") -> str:
    if value is None or value == "":
        return fallback

    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return str(value)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")


templates.env.filters["datetime"] = format_datetime


async def form_data(request: Request) -> dict[str, str]:
    body = (await request.body()).decode("utf-8")
    parsed = parse_qs(body, keep_blank_values=True)
    return {key: values[-1] for key, values in parsed.items()}


def render(request: Request, name: str, context: dict | None = None, status_code: int = 200) -> HTMLResponse:
    return templates.TemplateResponse(request, name, context or {}, status_code=status_code)


def enrich_dashboard_status(status: dict) -> dict:
    if status.get("root_ready") and not status.get("root_cert"):
        status["root_cert"] = cert_info(ROOT_CERT_PATH)
    if status.get("intermediate_ready") and not status.get("intermediate_cert"):
        status["intermediate_cert"] = cert_info(INTERMEDIATE_CERT_PATH)
    return status


def certificates_for_select() -> list[dict]:
    certificates = list_certificates()
    for cert in certificates:
        subject = cert.get("subject", "")
        cert["label"] = subject
        for part in subject.split(","):
            if part.strip().startswith("CN="):
                cert["label"] = part.strip()[3:]
                break
    return certificates


def certificate_page_context(extra: dict | None = None) -> dict:
    context = {
        "certificates": prepare_certificate_registry(),
        "certificate_registry": certificate_registry_options(),
        "approved_requests": list_requests("approved"),
        "profiles": sorted(ALLOWED_PROFILES),
        "default_days": "365",
    }
    if extra:
        context.update(extra)
    return context


def certificate_sort_value(cert: dict, sort_by: str) -> object:
    if sort_by in {"not_valid_before", "not_valid_after"}:
        try:
            return datetime.fromisoformat(str(cert.get(sort_by, "")))
        except ValueError:
            return datetime.min.replace(tzinfo=timezone.utc)
    return str(cert.get(sort_by, "")).lower()


def sort_certificates(certificates: list[dict], sort_value: str) -> list[dict]:
    sort_map = {
        "issued_desc": ("not_valid_before", True),
        "issued_asc": ("not_valid_before", False),
        "expires_asc": ("not_valid_after", False),
        "expires_desc": ("not_valid_after", True),
        "subject_asc": ("subject", False),
        "profile_asc": ("profile", False),
        "status_asc": ("display_status", False),
        "serial_asc": ("serial_number", False),
    }
    sort_by, reverse = sort_map.get(sort_value, sort_map["issued_desc"])
    return sorted(certificates, key=lambda cert: certificate_sort_value(cert, sort_by), reverse=reverse)


def certificate_registry_options(sort: str = "issued_desc", limit: str = "50") -> dict:
    allowed_limits = {"25", "50", "100", "250", "all"}
    allowed_sorts = {
        "issued_desc",
        "issued_asc",
        "expires_asc",
        "expires_desc",
        "subject_asc",
        "profile_asc",
        "status_asc",
        "serial_asc",
    }
    return {
        "sort": sort if sort in allowed_sorts else "issued_desc",
        "limit": limit if limit in allowed_limits else "50",
        "limits": ["25", "50", "100", "250", "all"],
        "sorts": [
            ("issued_desc", "Сначала новые"),
            ("issued_asc", "Сначала старые"),
            ("expires_asc", "Скоро истекают"),
            ("expires_desc", "Позже истекают"),
            ("subject_asc", "Subject A-Z"),
            ("profile_asc", "Профиль A-Z"),
            ("status_asc", "Статус A-Z"),
            ("serial_asc", "Serial A-Z"),
        ],
    }


def prepare_certificate_registry(sort: str = "issued_desc", limit: str = "50") -> list[dict]:
    options = certificate_registry_options(sort, limit)
    certificates = sort_certificates(list_certificates(), options["sort"])
    if options["limit"] == "all":
        return certificates
    return certificates[: int(options["limit"])]


def certificate_detail_context(serial: str, extra: dict | None = None) -> dict:
    cert = get_certificate(serial)
    try:
        verification = {"ok": True, "result": verify_certificate_path(Path(cert["cert_path"]), source="web")}
    except Exception as exc:
        verification = {"ok": False, "error": str(exc)}

    context = {"cert": cert, "verification": verification, "revocation_reasons": list(REASON_MAP)}
    if extra:
        context.update(extra)
    return context


def request_detail_context(request_id: int, extra: dict | None = None) -> dict:
    record = get_request(request_id)
    context = {"item": record, "validation": profile_validation(record)}
    if extra:
        context.update(extra)
    return context


def stand_certificate_path(value: str) -> Path:
    path = Path(value.strip())
    if not str(path):
        raise ValueError("Select a certificate, paste PEM, or provide a path inside data/.")
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Only relative paths inside data/ are allowed.")

    base = (Path.cwd() / BASE_DIR).resolve()
    resolved = (Path.cwd() / path).resolve()
    if resolved != base and base not in resolved.parents:
        raise ValueError("Only relative paths inside data/ are allowed.")

    return path


def clamp_limit(value: int) -> int:
    return max(25, min(value, 500))


def audit_action_label(action: str) -> str:
    labels = {
        "cert.issue": "Выпуск сертификата",
        "cert.revoke": "Отзыв сертификата",
        "crl.publish": "Публикация CRL",
        "req.submit": "Новая заявка",
        "req.approve": "Заявка одобрена",
        "req.reject": "Заявка отклонена",
        "verify": "Проверка сертификата",
        "web.start": "Запуск web",
        "web.stop": "Остановка web",
        "web.cleanup": "Очистка web",
        "web.key.generate": "Генерация web-ключа",
        "web.csr.generate": "Генерация web-CSR",
        "web.cert.issue": "Выпуск web-сертификата",
        "web.cert.register": "Регистрация web-сертификата",
        "web.cert.reuse": "Повторное использование web-сертификата",
        "web.cert.revoke": "Отзыв web-сертификата",
        "web.nginx.generate": "Генерация nginx",
        "web.nginx.test": "Проверка nginx",
        "web.nginx.reload": "Перезагрузка nginx",
    }
    return labels.get(action, action)


def audit_event_tone(event: dict) -> str:
    if event.get("result") in {"failed", "error"}:
        return "bad"
    action = str(event.get("action", ""))
    if action in {"cert.revoke", "req.reject", "web.cert.revoke"}:
        return "bad"
    if action in {"cert.issue", "crl.publish", "req.approve", "web.cert.issue", "web.cert.register", "web.cert.reuse"}:
        return "ok"
    return "neutral"


def audit_details(event: dict) -> list[tuple[str, object]]:
    hidden_keys = {"timestamp", "action", "result"}
    preferred = [
        "source",
        "serial_number",
        "request_id",
        "profile",
        "reason",
        "revoked_count",
        "cert_path",
        "csr_path",
        "crl_path",
        "host",
        "port",
        "pid",
        "stopped",
        "configure_nginx",
        "output",
        "message",
    ]
    ordered_keys = [key for key in preferred if key in event and event.get(key) not in (None, "")]
    ordered_keys.extend(
        key for key in event.keys() if key not in hidden_keys and key not in ordered_keys and event.get(key) not in (None, "")
    )
    return [(key, event[key]) for key in ordered_keys]


def prepare_audit_event(event: dict) -> dict:
    prepared = dict(event)
    action = str(prepared.get("action", "raw"))
    prepared["action_label"] = audit_action_label(action)
    prepared["tone"] = audit_event_tone(prepared)
    prepared["detail_items"] = audit_details(prepared)
    return prepared


def positive_days(value: str, default: int = 365) -> int:
    days = int(value.strip() or str(default))
    if days < 1:
        raise ValueError("Certificate validity must be at least 1 day.")
    return days


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    return render(request, "dashboard.html", {"status": enrich_dashboard_status(get_status()), "crl": crl_info()})


@router.get("/requests", response_class=HTMLResponse)
def requests_list(request: Request, status: str | None = None) -> HTMLResponse:
    return render(request, "requests_list.html", {"requests": list_requests(status), "status_filter": status or ""})


@router.get("/requests/new", response_class=HTMLResponse)
def request_new(request: Request) -> HTMLResponse:
    return render(request, "request_new.html", {"profile": "server_tls"})


@router.post("/requests")
async def request_create(request: Request) -> Response:
    data = await form_data(request)
    try:
        submit_csr_pem(data.get("csr", ""), data.get("profile", ""), source="web")
        return RedirectResponse("/requests", status_code=303)
    except Exception as exc:
        return render(request, "request_new.html", {"error": str(exc), "csr": data.get("csr", ""), "profile": data.get("profile", "server_tls")}, 400)


@router.get("/requests/{request_id}", response_class=HTMLResponse)
def request_detail(request: Request, request_id: int) -> HTMLResponse:
    return render(request, "request_detail.html", request_detail_context(request_id))


@router.post("/requests/{request_id}/approve")
def request_approve(request: Request, request_id: int) -> Response:
    try:
        approve_request(request_id, source="web")
        return RedirectResponse(f"/requests/{request_id}", status_code=303)
    except Exception as exc:
        return render(request, "request_detail.html", request_detail_context(request_id, {"error": str(exc)}), 400)


@router.post("/requests/{request_id}/reject")
async def request_reject(request: Request, request_id: int) -> Response:
    data = await form_data(request)
    try:
        reject_request(request_id, data.get("reason", "Rejected in web UI"), source="web")
        return RedirectResponse(f"/requests/{request_id}", status_code=303)
    except Exception as exc:
        return render(request, "request_detail.html", request_detail_context(request_id, {"error": str(exc)}), 400)


@router.post("/requests/{request_id}/issue")
def request_issue(request: Request, request_id: int) -> Response:
    try:
        record = issue_certificate_from_request(request_id, source="web")
        return RedirectResponse(f"/certificates/{record['serial_number']}", status_code=303)
    except Exception as exc:
        return render(request, "request_detail.html", request_detail_context(request_id, {"error": str(exc)}), 400)


@router.get("/certificates", response_class=HTMLResponse)
def certificates_list(request: Request, sort: str = "issued_desc", limit: str = "50") -> HTMLResponse:
    return render(
        request,
        "certificates_list.html",
        certificate_page_context(
            {
                "certificates": prepare_certificate_registry(sort, limit),
                "certificate_registry": certificate_registry_options(sort, limit),
            }
        ),
    )


@router.post("/certificates/issue/request")
async def certificate_issue_from_request(request: Request) -> Response:
    data = await form_data(request)
    try:
        request_id = int(data.get("request_id", "").strip())
        days = positive_days(data.get("days", "365"))
        record = issue_certificate_from_request(request_id, days=days, source="web")
        return RedirectResponse(f"/certificates/{record['serial_number']}", status_code=303)
    except Exception as exc:
        return render(
            request,
            "certificates_list.html",
            certificate_page_context(
                {
                    "error": str(exc),
                    "issue_request_id": data.get("request_id", ""),
                    "issue_request_days": data.get("days", "365"),
                }
            ),
            400,
        )


@router.post("/certificates/issue/csr")
async def certificate_issue_from_csr(request: Request) -> Response:
    data = await form_data(request)
    csr_pem = data.get("csr", "")
    profile = data.get("profile", "server_tls")
    days_value = data.get("days", "365")
    try:
        days = positive_days(days_value)
        with tempfile.NamedTemporaryFile("w", suffix=".csr.pem", delete=False, encoding="utf-8") as handle:
            handle.write(csr_pem)
            temp_path = Path(handle.name)
        try:
            record = issue_certificate_from_csr(temp_path, profile, days=days, source="web")
        finally:
            temp_path.unlink(missing_ok=True)
        return RedirectResponse(f"/certificates/{record['serial_number']}", status_code=303)
    except Exception as exc:
        return render(
            request,
            "certificates_list.html",
            certificate_page_context(
                {
                    "error": str(exc),
                    "csr": csr_pem,
                    "csr_profile": profile,
                    "csr_days": days_value,
                }
            ),
            400,
        )


@router.get("/certificates/{serial}", response_class=HTMLResponse)
def certificate_detail(request: Request, serial: str) -> HTMLResponse:
    return render(request, "certificate_detail.html", certificate_detail_context(serial))


@router.post("/certificates/{serial}/revoke")
async def certificate_revoke(request: Request, serial: str) -> Response:
    data = await form_data(request)
    try:
        revoke_certificate(serial, data.get("reason", "unspecified"), source="web")
        return RedirectResponse(f"/certificates/{serial}", status_code=303)
    except Exception as exc:
        return render(request, "certificate_detail.html", certificate_detail_context(serial, {"error": str(exc)}), 400)


@router.get("/crl", response_class=HTMLResponse)
def crl_page(request: Request) -> HTMLResponse:
    return render(request, "crl.html", {"crl": crl_info()})


@router.post("/crl/publish")
def crl_publish(request: Request) -> Response:
    try:
        publish_crl(source="web")
        return RedirectResponse("/crl", status_code=303)
    except Exception as exc:
        return render(request, "crl.html", {"crl": crl_info(), "error": str(exc)}, 400)


@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    limit: int = 100,
    action: str = "",
    source: str = "",
    result: str = "",
    q: str = "",
) -> HTMLResponse:
    limit = clamp_limit(limit)
    action_filter = action.strip()
    source_filter = source.strip()
    result_filter = result.strip()
    query_filter = q.strip()
    recent_events = list_events(500)
    events = [
        prepare_audit_event(event)
        for event in list_events(
            limit,
            action=action_filter or None,
            source=source_filter or None,
            result=result_filter or None,
            query=query_filter or None,
        )
    ]
    return render(
        request,
        "audit.html",
        {
            "events": events,
            "actions": event_values(recent_events, "action"),
            "sources": event_values(recent_events, "source"),
            "results": event_values(recent_events, "result"),
            "filters": {
                "limit": limit,
                "action": action_filter,
                "source": source_filter,
                "result": result_filter,
                "q": query_filter,
            },
        },
    )


@router.get("/verify", response_class=HTMLResponse)
def verify_page(request: Request) -> HTMLResponse:
    return render(request, "verify.html", {"certificates": certificates_for_select()})


@router.post("/verify")
async def verify_submit(request: Request) -> HTMLResponse:
    data = await form_data(request)
    certificates = certificates_for_select()
    try:
        selected_serial = data.get("serial", "").strip()
        if selected_serial:
            cert = get_certificate(selected_serial)
            result = verify_certificate_path(Path(cert["cert_path"]), source="web")
        elif data.get("pem", "").strip():
            result = verify_certificate_pem(data["pem"], source="web")
        else:
            result = verify_certificate_path(stand_certificate_path(data.get("path", "")), source="web")
        return render(
            request,
            "verify.html",
            {"result": result, "certificates": certificates, "selected_serial": selected_serial},
        )
    except Exception as exc:
        return render(
            request,
            "verify.html",
            {
                "error": str(exc),
                "pem": data.get("pem", ""),
                "path": data.get("path", ""),
                "certificates": certificates,
                "selected_serial": data.get("serial", ""),
            },
            400,
        )
