"""Тесты санитайзера — проверка что секреты удаляются, а код — нет."""
import sys
sys.path.insert(0, "/opt/audit-api")
from app.sanitizer import sanitize


def test_redacts_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
    result = sanitize(text)
    assert "PRIVATE_KEY_REDACTED" in result
    # Known limitation: only header is redacted, body requires multi-line PEM catch


def test_redacts_ssh_address():
    text = "ssh root@192.168.1.100"
    result = sanitize(text)
    assert "REDACTED_USER" in result
    assert "192.168.1.100" not in result


def test_redacts_evm_address():
    text = "0x4080C22B98E3EDE6Fcd31a3381e79D04d6CAAE84"
    result = sanitize(text)
    assert "CRYPTO_ADDRESS_REDACTED" in result
    assert "4080C22" not in result


def test_redacts_openai_key():
    text = "sk-abc123def456ghi789jkl012mno"
    result = sanitize(text)
    assert "REDACTED_KEY" in result
    assert "abc123" not in result


def test_redacts_bearer_token():
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"
    result = sanitize(text)
    assert "REDACTED_TOKEN" in result


def test_redacts_email():
    text = "Contact: user@example.com"
    result = sanitize(text)
    assert "EMAIL_REDACTED" in result


def test_redacts_phone():
    text = "Phone: +79161234567"
    result = sanitize(text)
    assert "PHONE_REDACTED" in result


def test_redacts_json_api_key():
    text = '{"api_key": "secret-key-12345"}'
    result = sanitize(text)
    assert "REDACTED" in result
    assert "secret-key-12345" not in result


def test_code_not_redacted():
    """Обычный код не должен быть затронут."""
    code = """
def calculate_hash(data: str) -> str:
    import hashlib
    return hashlib.sha256(data.encode()).hexdigest()

class UserService:
    def __init__(self, db):
        self.db = db
"""
    result = sanitize(code)
    assert "calculate_hash" in result
    assert "UserService" in result
    assert "hashlib" in result


def test_mixed_code_and_secrets():
    """Код с секретами — секреты удаляются, код остаётся."""
    text = """
API_KEY = "sk-abc123def456ghi789"
def process(url="https://api.example.com"):
    return requests.get(url)
"""
    result = sanitize(text)
    assert "process" in result
    assert "sk-abc123" not in result
    assert "REDACTED" in result


def test_preserves_numbers_and_urls():
    """Числа и URL без секретов сохраняются."""
    text = "Version 2.0, timeout=30, https://github.com/repo"
    result = sanitize(text)
    assert "2.0" in result
    assert "github.com" in result




def test_redacts_pem_body():
    """PEM-блок целиком (header + body + footer) красится."""
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7w6x3dP2x9L5\n-----END RSA PRIVATE KEY-----"
    result = sanitize(pem)
    assert "PEM_PRIVATE_KEY_REDACTED" in result
    assert "MIIEpAIBAAKCAQEA7w6x3dP2x9L5" not in result


def test_redacts_pem_ed25519():
    """PEM ED25519 ключ тоже ловится."""
    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----"
    result = sanitize(pem)
    assert "PEM_PRIVATE_KEY_REDACTED" in result

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS: {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL: {t.__name__} — {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR: {t.__name__} — {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
