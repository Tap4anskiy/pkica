from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from pkica.services.audit_service import list_events
from pkica.services.certificate_service import (
    get_certificate,
    issue_certificate_from_request,
    list_certificates,
    revoke_certificate,
    verify_certificate_path,
    verify_certificate_pem,
)
from pkica.services.crl_service import crl_info, publish_crl
from pkica.services.request_service import (
    approve_request,
    get_request,
    list_requests,
    profile_validation,
    reject_request,
    submit_csr_pem,
)
from pkica.services.status_service import get_status

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")


async def form_data(request: Request) -> dict[str, str]:
    body = (await request.body()).decode("utf-8")
    parsed = parse_qs(body, keep_blank_values=True)
    return {key: values[-1] for key, values in parsed.items()}


def render(request: Request, name: str, context: dict | None = None, status_code: int = 200) -> HTMLResponse:
    return templates.TemplateResponse(request, name, context or {}, status_code=status_code)


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    return render(request, "dashboard.html", {"status": get_status(), "crl": crl_info()})


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
    record = get_request(request_id)
    return render(request, "request_detail.html", {"item": record, "validation": profile_validation(record)})


@router.post("/requests/{request_id}/approve")
def request_approve(request_id: int) -> RedirectResponse:
    approve_request(request_id, source="web")
    return RedirectResponse(f"/requests/{request_id}", status_code=303)


@router.post("/requests/{request_id}/reject")
async def request_reject(request: Request, request_id: int) -> RedirectResponse:
    data = await form_data(request)
    reject_request(request_id, data.get("reason", "Rejected in web UI"), source="web")
    return RedirectResponse(f"/requests/{request_id}", status_code=303)


@router.post("/requests/{request_id}/issue")
def request_issue(request_id: int) -> RedirectResponse:
    record = issue_certificate_from_request(request_id, source="web")
    return RedirectResponse(f"/certificates/{record['serial_number']}", status_code=303)


@router.get("/certificates", response_class=HTMLResponse)
def certificates_list(request: Request) -> HTMLResponse:
    return render(request, "certificates_list.html", {"certificates": list_certificates()})


@router.get("/certificates/{serial}", response_class=HTMLResponse)
def certificate_detail(request: Request, serial: str) -> HTMLResponse:
    cert = get_certificate(serial)
    verification = None
    try:
        verification = {"ok": True, "result": verify_certificate_path(Path(cert["cert_path"]), source="web")}
    except Exception as exc:
        verification = {"ok": False, "error": str(exc)}
    return render(request, "certificate_detail.html", {"cert": cert, "verification": verification})


@router.post("/certificates/{serial}/revoke")
async def certificate_revoke(request: Request, serial: str) -> RedirectResponse:
    data = await form_data(request)
    revoke_certificate(serial, data.get("reason", "unspecified"), source="web")
    return RedirectResponse(f"/certificates/{serial}", status_code=303)


@router.get("/crl", response_class=HTMLResponse)
def crl_page(request: Request) -> HTMLResponse:
    return render(request, "crl.html", {"crl": crl_info()})


@router.post("/crl/publish")
def crl_publish() -> RedirectResponse:
    publish_crl(source="web")
    return RedirectResponse("/crl", status_code=303)


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, limit: int = 100) -> HTMLResponse:
    return render(request, "audit.html", {"events": list_events(limit)})


@router.get("/verify", response_class=HTMLResponse)
def verify_page(request: Request) -> HTMLResponse:
    return render(request, "verify.html", {})


@router.post("/verify")
async def verify_submit(request: Request) -> HTMLResponse:
    data = await form_data(request)
    try:
        if data.get("pem", "").strip():
            result = verify_certificate_pem(data["pem"], source="web")
        else:
            path = Path(data.get("path", ""))
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Only relative paths inside the stand are allowed")
            result = verify_certificate_path(path, source="web")
        return render(request, "verify.html", {"result": result})
    except Exception as exc:
        return render(request, "verify.html", {"error": str(exc), "pem": data.get("pem", ""), "path": data.get("path", "")}, 400)
