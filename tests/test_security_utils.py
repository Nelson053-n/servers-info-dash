from app import main


def test_hash_and_verify_password_roundtrip():
    password = "S3cure-Pass-123"
    hashed = main._hash_password(password)
    assert hashed.startswith("pbkdf2$")
    assert main._verify_password(password, hashed)


def test_verify_password_rejects_wrong_password():
    hashed = main._hash_password("correct-password")
    assert not main._verify_password("wrong-password", hashed)


def test_ip_allowed_with_cidr_and_exact_ip():
    networks = ["192.168.10.0/24", "10.0.0.5"]
    assert main._ip_allowed("192.168.10.93", networks)
    assert main._ip_allowed("10.0.0.5", networks)
    assert not main._ip_allowed("10.0.0.6", networks)


def test_ip_allowed_rejects_invalid_ip():
    assert not main._ip_allowed("invalid_ip", ["192.168.1.0/24"])