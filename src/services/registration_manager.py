# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, Any

from faker import Faker
from curl_cffi.requests import AsyncSession

from ..core.database import Database
from .proxy_manager import ProxyManager


@dataclass
class RegistrationContext:
    registration_id: str
    email: str
    password: str
    name: str
    birthday: str  # YYYY-MM-DD
    source_invite_token_id: Optional[int] = None
    code: Optional[str] = None
    extra: Dict[str, Any] = None  # placeholder for csrf/device/cookies when implemented

    def to_dict(self) -> Dict[str, Any]:
        return {
            "registration_id": self.registration_id,
            "email": self.email,
            "password": self.password,
            "name": self.name,
            "birthday": self.birthday,
            "source_invite_token_id": self.source_invite_token_id,
            "code": self.code,
            "extra": self.extra or {},
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "RegistrationContext":
        return RegistrationContext(
            registration_id=d["registration_id"],
            email=d["email"],
            password=d["password"],
            name=d["name"],
            birthday=d["birthday"],
            source_invite_token_id=d.get("source_invite_token_id"),
            code=d.get("code"),
            extra=d.get("extra") or {},
        )


class RegistrationManager:
    """
    Minimal skeleton for two-step registration:
    - start(email, ...) -> creates RegistrationContext and picks an invite source
    - verify(reg_id, code) -> TODO: implement HTTP flow using curl_cffi based on HAR
    """

    def __init__(self, db: Database, proxy_manager: ProxyManager):
        self.db = db
        self.proxy_manager = proxy_manager
        self.fake = Faker()
        self.base_dir = Path("tmp/registrations")
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _ctx_path(self, registration_id: str) -> Path:
        return self.base_dir / f"{registration_id}.json"

    async def start(self, email: str, password: Optional[str] = None,
                    name: Optional[str] = None, birthday: Optional[str] = None,
                    use_proxy: bool = False) -> RegistrationContext:
        if not password:
            # simple random password; real rules can be applied later
            password = self.fake.password(length=12, special_chars=True, digits=True, upper_case=True, lower_case=True)
        if not name:
            name = f"{self.fake.first_name()} {self.fake.last_name()}"
        if not birthday:
            # default to adult
            birthday = "1996-01-01"

        # pick an invite source token
        invite_sources = await self.db.get_tokens_with_available_invites(limit=1)
        source_id = invite_sources[0].id if invite_sources else None

        reg_id = uuid.uuid4().hex
        ctx = RegistrationContext(
            registration_id=reg_id,
            email=email,
            password=password,
            name=name,
            birthday=birthday,
            source_invite_token_id=source_id,
            extra={"use_proxy": bool(use_proxy)},
        )
        # Persist initial context
        self._ctx_path(reg_id).write_text(json.dumps(ctx.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

        # Kick off remote flow to trigger email OTP
        headers_base = {
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
        }
        proxy_url = None
        if use_proxy:
            proxy_url = await self.proxy_manager.get_proxy_url()

        kwargs_common: Dict[str, Any] = {"timeout": 30, "impersonate": "chrome"}
        if proxy_url:
            kwargs_common["proxy"] = proxy_url

        def build_authorize_url() -> str:
            from urllib.parse import urlencode
            client_id = "app_X8zY6vW2pQ9tR3dE7nK1jL5gH"
            device_id = str(uuid.uuid4())
            ext_oai_did = device_id
            auth_session_logging_id = str(uuid.uuid4())
            state = uuid.uuid4().hex
            params = {
                "client_id": client_id,
                "scope": "openid email profile offline_access model.request model.read organization.read organization.write",
                "response_type": "code",
                "redirect_uri": "https://chatgpt.com/api/auth/callback/openai",
                "audience": "https://api.openai.com/v1",
                "prompt": "login",
                "screen_hint": "login_or_signup",
                "device_id": device_id,
                "ext-oai-did": ext_oai_did,
                "auth_session_logging_id": auth_session_logging_id,
                "state": state,
            }
            return f"https://auth.openai.com/api/accounts/authorize?{urlencode(params)}"

        # Use a temporary session to reach OTP send step and capture cookies for verify
        async with AsyncSession() as session:
            headers = headers_base | {
                "Origin": "https://chatgpt.com",
                "Referer": "https://chatgpt.com/auth/login?next=%2Fsora%2F",
            }
            def persist(stage: str, resp=None):
                ctx.extra["last_stage"] = stage
                if resp is not None:
                    ctx.extra["last_status"] = getattr(resp, "status_code", None)
                    try:
                        txt = resp.text
                        if txt and len(txt) > 200:
                            txt = txt[:200]
                        ctx.extra["last_text_preview"] = txt
                    except Exception:
                        pass
                self._ctx_path(reg_id).write_text(json.dumps(ctx.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

            # A0. land on chatgpt login (set base cookies)
            _ = await session.get("https://chatgpt.com/auth/login?next=%2Fsora%2F", headers=headers, **kwargs_common)
            persist("login_page_loaded")
            # A. authorize
            r = await session.get(build_authorize_url(), headers=headers, **kwargs_common)
            if r.status_code not in (200, 302, 303):
                persist("authorize_failed", r)
                raise RuntimeError(f"authorize failed: {r.status_code}")
            persist("authorized", r)
            # B. submit email
            payload = {"username": {"value": email, "kind": "email"}, "screen_hint": "login_or_signup"}
            headers_auth = headers_base | {"Origin": "https://auth.openai.com", "Referer": "https://auth.openai.com/u/login/identifier"}
            r = await session.post("https://auth.openai.com/api/accounts/authorize/continue", headers=headers_auth, json=payload, **kwargs_common)
            if r.status_code not in (200, 302, 303):
                persist("authorize_continue_failed", r)
                raise RuntimeError(f"authorize continue failed: {r.status_code}")
            persist("authorize_continue_ok", r)
            # C. register (email+password)
            payload = {"password": password, "username": email}
            headers_reg = headers_base | {"Origin": "https://auth.openai.com", "Referer": "https://auth.openai.com/create-account/password"}
            r = await session.post("https://auth.openai.com/api/accounts/user/register", headers=headers_reg, json=payload, **kwargs_common)
            if r.status_code not in (200, 201, 204, 302, 303):
                persist("register_failed", r)
                raise RuntimeError(f"register failed: {r.status_code}")
            persist("registered", r)
            # D. send OTP
            headers_otp = headers_base | {"Origin": "https://auth.openai.com", "Referer": "https://auth.openai.com/email-verification"}
            r = await session.get("https://auth.openai.com/api/accounts/email-otp/send", headers=headers_otp, **kwargs_common)
            persist("otp_send_called", r)
            # Save cookies for verify stage
            try:
                cookie_header = "; ".join([f"{k}={v}" for k, v in session.cookies.items()])
            except Exception:
                cookie_header = None
            # Update context with session artifacts
            ctx.extra.update({
                "cookie": cookie_header,
                "last_stage": "otp_sent",
                "proxy_url": proxy_url,
            })
            self._ctx_path(reg_id).write_text(json.dumps(ctx.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

        return ctx

    async def verify(self, registration_id: str, code: str) -> Dict[str, Any]:
        """
        Execute HTTP signup + OTP verification + session establishment to obtain Access Token.
        Endpoints derived from HAR:
          - GET  https://auth.openai.com/api/accounts/authorize?... (establish session)
          - POST https://auth.openai.com/api/accounts/authorize/continue  (with email)
          - POST https://auth.openai.com/api/accounts/user/register       (with password)
          - GET  https://auth.openai.com/api/accounts/email-otp/send      (ensure code sent)
          - POST https://auth.openai.com/api/accounts/email-otp/validate  (submit code)
          - GET  https://sora.chatgpt.com/                                (prime cookies)
          - GET  https://sora.chatgpt.com/api/auth/session                (obtain accessToken)
        """
        p = self._ctx_path(registration_id)
        if not p.exists():
            raise FileNotFoundError("registration not found")
        ctx = RegistrationContext.from_dict(json.loads(p.read_text(encoding="utf-8")))
        ctx.code = code
        p.write_text(json.dumps(ctx.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

        # Prepare HTTP session
        headers_base = {
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
        }
        proxy_url = None
        if ctx.extra and ctx.extra.get("use_proxy"):
            proxy_url = await self.proxy_manager.get_proxy_url()

        kwargs_common: Dict[str, Any] = {
            "timeout": 30,
            "impersonate": "chrome",
        }
        if proxy_url:
            kwargs_common["proxy"] = proxy_url

        def build_authorize_url() -> str:
            from urllib.parse import urlencode
            client_id = "app_X8zY6vW2pQ9tR3dE7nK1jL5gH"  # observed in HAR
            device_id = str(uuid.uuid4())
            ext_oai_did = device_id
            auth_session_logging_id = str(uuid.uuid4())
            state = uuid.uuid4().hex
            params = {
                "client_id": client_id,
                "scope": "openid email profile offline_access model.request model.read organization.read organization.write",
                "response_type": "code",
                "redirect_uri": "https://chatgpt.com/api/auth/callback/openai",
                "audience": "https://api.openai.com/v1",
                "prompt": "login",
                "screen_hint": "login_or_signup",
                "device_id": device_id,
                "ext-oai-did": ext_oai_did,
                "auth_session_logging_id": auth_session_logging_id,
                "state": state,
            }
            return f"https://auth.openai.com/api/accounts/authorize?{urlencode(params)}"

        async with AsyncSession() as session:
            # A. kick off authorize to set cookies
            headers = headers_base | {
                "Origin": "https://chatgpt.com",
                "Referer": "https://chatgpt.com/auth/login?next=%2Fsora%2F",
            }
            # A0. load login page to set base cookies
            _ = await session.get("https://chatgpt.com/auth/login?next=%2Fsora%2F", headers=headers, **kwargs_common)
            r = await session.get(build_authorize_url(), headers=headers, **kwargs_common)
            if r.status_code not in (200, 302, 303):
                return {"implemented": False, "stage": "authorize", "status": r.status_code, "captcha_required": True}

            # B. submit email (authorize/continue)
            payload = {"username": {"value": ctx.email, "kind": "email"}, "screen_hint": "login_or_signup"}
            headers_auth = headers_base | {"Origin": "https://auth.openai.com", "Referer": "https://auth.openai.com/u/login/identifier"}
            r = await session.post("https://auth.openai.com/api/accounts/authorize/continue", headers=headers_auth, json=payload, **kwargs_common)
            if r.status_code != 200:
                return {"implemented": False, "stage": "authorize_continue", "status": r.status_code}

            # C. register (email + password)
            payload = {"password": ctx.password, "username": ctx.email}
            headers_reg = headers_base | {"Origin": "https://auth.openai.com", "Referer": "https://auth.openai.com/create-account/password"}
            r = await session.post("https://auth.openai.com/api/accounts/user/register", headers=headers_reg, json=payload, **kwargs_common)
            if r.status_code != 200:
                return {"implemented": False, "stage": "register", "status": r.status_code, "detail": r.text[:200]}

            # D. ensure OTP send (optional)
            headers_otp = headers_base | {"Origin": "https://auth.openai.com", "Referer": "https://auth.openai.com/email-verification"}
            _ = await session.get("https://auth.openai.com/api/accounts/email-otp/send", headers=headers_otp, **kwargs_common)

            # E. validate OTP
            # Reuse cookies from start if available for continuity
            if ctx.extra and ctx.extra.get("cookie"):
                headers_auth = headers_auth | {"Cookie": ctx.extra["cookie"]}
            r = await session.post("https://auth.openai.com/api/accounts/email-otp/validate", headers=headers_auth, json={"code": code}, **kwargs_common)
            if r.status_code != 200:
                return {"implemented": False, "stage": "email_otp_validate", "status": r.status_code, "detail": r.text[:200]}

            # F. visit Sora domain then fetch session
            headers_sora = headers_base | {"Origin": "https://sora.chatgpt.com", "Referer": "https://sora.chatgpt.com/"}
            _ = await session.get("https://sora.chatgpt.com/", headers=headers_sora, **kwargs_common)
            r = await session.get("https://sora.chatgpt.com/api/auth/session", headers=headers_sora, **kwargs_common)
            if r.status_code != 200:
                # fallback try chatgpt.com session endpoint
                r2 = await session.get("https://chatgpt.com/api/auth/session", headers=headers, **kwargs_common)
                if r2.status_code == 200:
                    data = r2.json()
                    at = data.get("accessToken") or data.get("access_token")
                    if at:
                        return {"implemented": True, "access_token": at, "email": ctx.email, "source_invite_token_id": ctx.source_invite_token_id}
                return {"implemented": False, "stage": "sora_session", "status": r.status_code, "captcha_required": True}

            data = r.json()
            at = data.get("accessToken") or data.get("access_token")
            if not at:
                return {"implemented": False, "stage": "sora_session_parse", "status": r.status_code}

            return {
                "implemented": True,
                "access_token": at,
                "email": ctx.email,
                "source_invite_token_id": ctx.source_invite_token_id,
            }
