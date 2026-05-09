#!/usr/bin/env python3
"""Focused regression checks for OAuth signup redirect continuation."""

import datetime
import html
import os
import re
import sys
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

os.environ["FLASK_SECRET_KEY"] = "test-secret-for-oauth-continuation"
os.environ["FLASK_MAIL_USERNAME"] = "test@example.com"
os.environ["FLASK_MAIL_PASSWORD"] = "test-password"
os.environ["FLASK_MAIL_DEFAULT_SENDER"] = "test@example.com"
os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
os.environ["FLASK_ALLOWED_REDIRECT_DOMAINS"] = "https://vinylvote.bynolo.ca,http://localhost:6002"
os.environ["TURNSTILE_ENABLED"] = "False"

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import jwt
from werkzeug.security import generate_password_hash

from auth_server.app import create_app, db
import auth_server.app.routes as routes
from auth_server.app.models import ClientApplication, User
from auth_server.app.oauth_utils import ScopeManager
from auth_server.app.security_utils import validate_redirect_url


CLIENT_ID = "haW8KUuGwqihxTq0TSVvFRC5-EHTdXZcqCxBast6mGo"
REDIRECT_URI = "https://vinylvote.bynolo.ca/oauth/callback"
STATE = "TiBupwThtHpC0uNfbn3eQs15zOv-Zn5roMJFozb6xO0"
OAUTH_URL = (
    "/oauth/authorize"
    f"?client_id={CLIENT_ID}"
    f"&redirect_uri={REDIRECT_URI}"
    "&scope=id,username,email,display_name,is_verified"
    f"&state={STATE}"
)


def assert_equal(actual, expected, message):
    if actual != expected:
        raise AssertionError(f"{message}: expected {expected!r}, got {actual!r}")


def assert_true(value, message):
    if not value:
        raise AssertionError(message)


def create_verified_user(username, email, password="Password123"):
    user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        is_verified=True,
    )
    db.session.add(user)
    db.session.commit()
    return user


def create_oauth_client(created_by):
    client = ClientApplication(
        client_id=CLIENT_ID,
        client_secret="client-secret",
        name="VinylVote",
        description="VinylVote test client",
        website_url="https://vinylvote.bynolo.ca",
        redirect_uris=f'["{REDIRECT_URI}"]',
        created_by=created_by,
    )
    db.session.add(client)
    db.session.commit()
    return client


def test_redirect_validation(app):
    with app.test_request_context("/"):
        assert_equal(validate_redirect_url(OAUTH_URL), OAUTH_URL, "relative OAuth URL should be valid")
        assert_equal(validate_redirect_url(REDIRECT_URI), REDIRECT_URI, "configured client origin should be valid")
        assert_equal(validate_redirect_url("//evil.com"), None, "protocol-relative URL should be blocked")
        assert_equal(validate_redirect_url("javascript:alert(1)"), None, "dangerous scheme should be blocked")
        assert_equal(
            validate_redirect_url("https://vinylvote.bynolo.ca.evil.com/oauth/callback"),
            None,
            "host prefix spoofing should be blocked",
        )


def test_register_form_preserves_full_redirect(client):
    response = client.get("/register", query_string={"redirect": OAUTH_URL})
    body = response.get_data(as_text=True)
    match = re.search(r'<form[^>]+id="register-form"[^>]+action="([^"]+)"', body)
    assert_true(match, "register form action should be present")

    action = html.unescape(match.group(1))
    redirect_value = parse_qs(urlparse(action).query).get("redirect", [None])[0]
    assert_equal(redirect_value, OAUTH_URL, "register form should preserve the full nested OAuth URL")


def test_email_verify_profile_and_oauth_resume(app, client):
    with app.app_context():
        admin = create_verified_user("admin-user", "admin@example.com")
        create_oauth_client(admin.id)
        pending = User(
            username="new-oauth-user",
            email="new-oauth@example.com",
            password_hash=generate_password_hash("Password123"),
            is_verified=False,
        )
        db.session.add(pending)
        db.session.commit()

        token = jwt.encode(
            {
                "user_id": pending.id,
                "redirect": OAUTH_URL,
                "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=30),
            },
            app.config["SECRET_KEY"],
            algorithm="HS256",
        )

    verify_response = client.get(f"/verify-email/{token}")
    assert_equal(verify_response.status_code, 302, "verify email should redirect")
    verify_location = verify_response.headers["Location"]
    assert_true(verify_location.startswith("/profile/complete?"), "verify email should require profile completion")
    assert_equal(
        parse_qs(urlparse(verify_location).query).get("redirect", [None])[0],
        OAUTH_URL,
        "profile completion should receive the OAuth continuation",
    )

    profile_response = client.post(
        verify_location,
        data={"display_name": "New OAuth User", "submit": "Complete Profile"},
    )
    assert_equal(profile_response.status_code, 302, "profile completion should redirect")
    assert_equal(profile_response.headers["Location"], OAUTH_URL, "profile completion should resume OAuth")

    consent_response = client.get(profile_response.headers["Location"])
    assert_equal(consent_response.status_code, 200, "resumed OAuth request should show consent")

    approve_response = client.post(
        "/oauth/authorize",
        data={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "id,username,email,display_name,is_verified",
            "state": STATE,
            "action": "approve",
        },
    )
    assert_equal(approve_response.status_code, 302, "OAuth approval should redirect to client")
    callback = approve_response.headers["Location"]
    parsed_callback = urlparse(callback)
    callback_query = parse_qs(parsed_callback.query)
    assert_equal(f"{parsed_callback.scheme}://{parsed_callback.netloc}{parsed_callback.path}", REDIRECT_URI, "callback URL should match registered redirect URI")
    assert_equal(callback_query.get("state", [None])[0], STATE, "OAuth state should be preserved")
    assert_true(callback_query.get("code", [None])[0], "OAuth callback should include an authorization code")


def test_password_login_requires_profile_before_oauth(app, client):
    with app.app_context():
        create_verified_user("needs-profile", "needs-profile@example.com")

    response = client.post(
        "/login",
        query_string={"redirect": OAUTH_URL},
        data={"username": "needs-profile", "password": "Password123"},
    )
    assert_equal(response.status_code, 302, "password login should redirect")
    location = response.headers["Location"]
    assert_true(location.startswith("/profile/complete?"), "password login should require profile completion")
    assert_equal(
        parse_qs(urlparse(location).query).get("redirect", [None])[0],
        OAUTH_URL,
        "password login should preserve OAuth continuation for profile completion",
    )


def test_password_reset_preserves_oauth_continuation(app, client):
    with app.app_context():
        create_verified_user("reset-user", "reset-user@example.com")

    login_response = client.get("/login", query_string={"redirect": OAUTH_URL})
    login_body = login_response.get_data(as_text=True)
    assert_true(
        "forgot-password?redirect=" in login_body,
        "login page should pass OAuth continuation to forgot-password link",
    )

    forgot_response = client.get("/forgot-password", query_string={"redirect": OAUTH_URL})
    forgot_body = forgot_response.get_data(as_text=True)
    match = re.search(r'<form[^>]+id="forgot-password-form"[^>]+action="([^"]+)"', forgot_body)
    assert_true(match, "forgot password form action should be present")
    forgot_action = html.unescape(match.group(1))
    assert_equal(
        parse_qs(urlparse(forgot_action).query).get("redirect", [None])[0],
        OAUTH_URL,
        "forgot password form should preserve OAuth continuation",
    )

    outbox = []
    with patch.object(routes.mail, "send", side_effect=lambda msg: outbox.append(msg)):
        sent_response = client.post(
            forgot_action,
            data={"email": "reset-user@example.com"},
        )
        assert_equal(sent_response.status_code, 200, "forgot password submit should render sent page")
        assert_equal(len(outbox), 1, "forgot password submit should send one reset email")
        email_body = outbox[0].html

    link_match = re.search(r'href="([^"]+/reset-password/[^"]+)"', email_body)
    assert_true(link_match, "password reset email should contain reset link")
    reset_path = urlparse(html.unescape(link_match.group(1))).path

    reset_get = client.get(reset_path)
    assert_equal(reset_get.status_code, 200, "reset password link should render form")

    reset_post = client.post(
        reset_path,
        data={"password": "NewPassword123", "confirm": "NewPassword123"},
    )
    assert_equal(reset_post.status_code, 302, "successful reset should redirect to login")
    login_location = reset_post.headers["Location"]
    assert_true(login_location.startswith("/login?"), "reset success should return to login")
    assert_equal(
        parse_qs(urlparse(login_location).query).get("redirect", [None])[0],
        OAUTH_URL,
        "reset success login redirect should preserve OAuth continuation",
    )


def main():
    app = create_app()
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        MAIL_SUPPRESS_SEND=True,
        SERVER_NAME="auth-keyn.bynolo.ca",
        PREFERRED_URL_SCHEME="https",
    )

    with app.app_context():
        db.drop_all()
        db.create_all()
        ScopeManager.initialize_default_scopes()

    client = app.test_client()
    test_redirect_validation(app)
    test_register_form_preserves_full_redirect(client)
    test_email_verify_profile_and_oauth_resume(app, client)

    with app.app_context():
        db.drop_all()
        db.create_all()
        ScopeManager.initialize_default_scopes()

    client = app.test_client()
    test_password_login_requires_profile_before_oauth(app, client)
    test_password_reset_preserves_oauth_continuation(app, client)
    print("OAuth continuation regression checks passed.")


if __name__ == "__main__":
    main()
