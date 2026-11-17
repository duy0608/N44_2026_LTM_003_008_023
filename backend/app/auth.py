"""Đăng nhập: mật khẩu băm PBKDF2 và token có chữ ký HMAC, chỉ dùng thư viện chuẩn.

Ai vào được Dashboard là điều khiển được firewall, nên mọi API quản lý (trừ /api/login)
đều đòi token hợp lệ trong tiêu đề `Authorization: Bearer <token>`.
"""
import base64
import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque
from typing import Optional

from fastapi import Header, HTTPException, Request

from . import config, db

_ITERATIONS = 200_000
_SECRET = secrets.token_bytes(32)  # đổi mỗi lần khởi động lại: token cũ hết hiệu lực


# ----- Băm mật khẩu -----

def hash_password(password: str, salt: Optional[bytes] = None, iterations: int = _ITERATIONS) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt_hex, hash_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(digest.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def ensure_admin() -> Optional[str]:
    """Tạo tài khoản quản trị lần đầu. Trả về mật khẩu tự sinh (để in ra) hoặc None."""
    if db.count_users() > 0:
        return None
    generated = None
    password = config.ADMIN_PASSWORD
    if not password:
        password = generated = secrets.token_urlsafe(9)
    db.set_user(config.ADMIN_USER, hash_password(password))
    return generated


# ----- Token -----

def _sign(payload: str) -> str:
    return hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()


def make_token(username: str, ttl: Optional[int] = None) -> str:
    expires = int(time.time()) + (ttl if ttl is not None else config.TOKEN_TTL)
    payload = f"{username}|{expires}"
    body = base64.urlsafe_b64encode(payload.encode()).decode()
    return f"{body}.{_sign(payload)}"


def verify_token(token: str) -> Optional[str]:
    """Trả về tên người dùng nếu token đúng chữ ký và chưa hết hạn."""
    try:
        body, sig = token.split(".", 1)
        payload = base64.urlsafe_b64decode(body.encode()).decode()
        if not hmac.compare_digest(sig, _sign(payload)):
            return None
        username, expires = payload.rsplit("|", 1)
        if int(expires) < time.time():
            return None
        return username
    except (ValueError, TypeError):
        return None


# ----- Chống dò mật khẩu -----

_fails = defaultdict(deque)  # ip -> thời điểm các lần đăng nhập sai


def _recent_fails(ip: str) -> deque:
    q = _fails[ip]
    cutoff = time.time() - config.LOGIN_FAIL_WINDOW
    while q and q[0] < cutoff:
        q.popleft()
    return q


def check_not_locked(ip: str) -> None:
    if len(_recent_fails(ip)) >= config.LOGIN_MAX_FAILS:
        raise HTTPException(status_code=429, detail="Đăng nhập sai quá nhiều lần, thử lại sau ít phút")


def record_fail(ip: str) -> None:
    _recent_fails(ip).append(time.time())


def clear_fails(ip: str) -> None:
    _fails.pop(ip, None)


def login(username: str, password: str, request: Request) -> str:
    ip = request.client.host if request.client else "unknown"
    check_not_locked(ip)
    stored = db.get_user_hash(username)
    # Luôn băm một lần dù không có người dùng, để thời gian phản hồi không lộ tên tài khoản
    ok = verify_password(password, stored or hash_password("x", salt=b"0" * 16, iterations=1000))
    if not stored or not ok:
        record_fail(ip)
        raise HTTPException(status_code=401, detail="Sai tên đăng nhập hoặc mật khẩu")
    clear_fails(ip)
    return make_token(username)


# ----- Dependency bảo vệ API -----

def require_auth(authorization: Optional[str] = Header(default=None)) -> Optional[str]:
    if not config.AUTH_ENABLED:
        return None
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Cần đăng nhập")
    user = verify_token(authorization[7:].strip())
    if not user:
        raise HTTPException(status_code=401, detail="Token không hợp lệ hoặc đã hết hạn")
    return user
