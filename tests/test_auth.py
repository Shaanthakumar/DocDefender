import pytest
from services.auth_service import hash_password, verify_password, create_access_token, decode_access_token

def test_argon2_password_hashing():
    raw_pass = "SecureAdminPass2026!"
    hashed = hash_password(raw_pass)
    assert hashed != raw_pass
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("WrongPass", hashed) is False

def test_jwt_token_roundtrip():
    user_data = {"sub": "101", "email": "admin@docsdefender.local", "role": "administrator"}
    token = create_access_token(user_data)
    assert isinstance(token, str)
    
    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded["sub"] == "101"
    assert decoded["email"] == "admin@docsdefender.local"
    assert decoded["role"] == "administrator"

def test_jwt_token_invalid():
    invalid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature"
    assert decode_access_token(invalid_token) is None
