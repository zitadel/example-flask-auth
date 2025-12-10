import base64
import hashlib
import secrets
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode

import requests
from flask import (
    Blueprint,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from lib.config import config
from lib.message import get_message
from lib.scopes import ZITADEL_SCOPES

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

REQUEST_TIMEOUT = 5


def get_well_known_url(domain: str) -> str:
    return f"{domain}/.well-known/openid-configuration"


def generate_pkce() -> Tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


def get_session() -> Optional[Dict[str, Any]]:
    return session.get("auth_session")


@auth_bp.route("/signin")
def signin() -> Any:
    error = request.args.get("error")
    providers = [{"id": "zitadel", "name": "ZITADEL", "callbackUrl": config.ZITADEL_CALLBACK_URL}]
    return render_template(
        "auth/signin.html",
        providers=providers,
        callbackUrl=request.args.get("callbackUrl") or config.ZITADEL_POST_LOGIN_URL,
        message=get_message(error, "signin-error") if error else None,
    )


@auth_bp.route("/signin/zitadel", methods=["POST"])
def signin_zitadel() -> Any:
    verifier, challenge = generate_pkce()
    session["pkce_verifier"] = verifier
    well_known = requests.get(
        get_well_known_url(config.ZITADEL_DOMAIN),
        timeout=REQUEST_TIMEOUT,
    ).json()
    auth_endpoint: str = well_known["authorization_endpoint"]
    params = {
        "client_id": config.ZITADEL_CLIENT_ID,
        "redirect_uri": config.ZITADEL_CALLBACK_URL,
        "response_type": "code",
        "scope": ZITADEL_SCOPES,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return redirect(f"{auth_endpoint}?{urlencode(params)}")


@auth_bp.route("/callback")
def callback() -> Any:
    code = request.args.get("code")
    if not code:
        return redirect(url_for("auth.error_page", error="callback"))

    verifier = session.get("pkce_verifier")
    if not verifier:
        return redirect(url_for("auth.error_page", error="verification"))

    well_known = requests.get(
        get_well_known_url(config.ZITADEL_DOMAIN),
        timeout=REQUEST_TIMEOUT,
    ).json()
    token_endpoint: str = well_known["token_endpoint"]
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.ZITADEL_CALLBACK_URL,
        "client_id": config.ZITADEL_CLIENT_ID,
        "code_verifier": verifier,
    }
    token_res = requests.post(token_endpoint, data=data, timeout=REQUEST_TIMEOUT)
    if token_res.status_code != 200:
        return redirect(url_for("auth.error_page", error="callback"))

    tokens: Dict[str, Any] = token_res.json()
    access_token = tokens.get("access_token")

    userinfo_endpoint: str = well_known["userinfo_endpoint"]
    userinfo = requests.get(
        userinfo_endpoint,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=REQUEST_TIMEOUT,
    ).json()

    session["auth_session"] = {
        "user": userinfo,
        "access_token": access_token,
        "id_token": tokens.get("id_token"),
    }

    post_login = request.args.get("callbackUrl") or config.ZITADEL_POST_LOGIN_URL
    return redirect(post_login)


@auth_bp.route("/logout", methods=["POST"])
def logout() -> Any:
    session.clear()
    well_known = requests.get(get_well_known_url(config.ZITADEL_DOMAIN), timeout=REQUEST_TIMEOUT).json()
    end_session = well_known.get("end_session_endpoint")
    if end_session:
        params = {
            "post_logout_redirect_uri": config.ZITADEL_POST_LOGOUT_URL,
            "client_id": config.ZITADEL_CLIENT_ID,
        }
        return redirect(f"{end_session}?{urlencode(params)}")
    return redirect(config.ZITADEL_POST_LOGOUT_URL)


@auth_bp.route("/error")
def error_page() -> Any:
    error_code = request.args.get("error")
    msg = get_message(error_code, "auth-error")
    return render_template("auth/error.html", **msg)


@auth_bp.route("/logout/callback")
def logout_callback() -> Any:
    return render_template("auth/logout/success.html")


@auth_bp.route("/logout/error")
def logout_error() -> Any:
    return render_template("auth/logout/error.html")


def register_auth_routes(app: Any) -> None:
    app.register_blueprint(auth_bp)
