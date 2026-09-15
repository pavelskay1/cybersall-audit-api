"""Тесты unified splitter — fast-path, fallback, merge small blocks."""
import sys
sys.path.insert(0, "/opt/audit-api")


def test_small_code_returns_one_block():
    """Код <16K символов — один блок без LLM-сплита."""
    from app.orchestrator import split_into_blocks
    code = "def foo():\n    return 42\n"
    blocks = split_into_blocks(code)
    assert len(blocks) == 1
    assert blocks[0]["name"] == "whole_code"
    assert blocks[0]["code"] == code


def test_empty_code():
    """Пустой код — один блок (не краш)."""
    from app.orchestrator import split_into_blocks
    blocks = split_into_blocks("")
    assert len(blocks) >= 1


def test_exact_limit_code():
    """Код ровно MAX_BLOCK_CHARS — один блок."""
    from app.orchestrator import split_into_blocks, MAX_BLOCK_CHARS
    code = "x = 1\n" * (MAX_BLOCK_CHARS // 6)
    blocks = split_into_blocks(code)
    assert len(blocks) == 1


def test_file_index_extraction():
    """_file_index находит функции в коде."""
    from app.orchestrator import _file_index
    code = """
def foo():
    pass

def bar():
    pass

constructor() {}

receive() {}
"""
    idx = _file_index(code)
    assert "foo" in idx
    assert "bar" in idx
    assert "constructor" in idx
    assert "receive" in idx


def test_file_index_empty():
    """_file_index на пустом коде — пустая строка."""
    from app.orchestrator import _file_index
    assert _file_index("print('hello')") == ""


def test_merge_small_blocks():
    """_merge_small_blocks склеивает мелкие блоки."""
    from app.orchestrator import _merge_small_blocks
    blocks = [
        {"name": "a", "code": "x = 1", "context": "", "focus": ""},
        {"name": "b", "code": "y = 2", "context": "", "focus": ""},
        {"name": "c", "code": "z = 3\n" * 2000, "context": "", "focus": ""},
    ]
    merged = _merge_small_blocks(blocks)
    assert len(merged) < 3  # a и b склеились


def test_fallback_blocks():
    """_fallback_blocks режет код по символам."""
    from app.orchestrator import _fallback_blocks, MAX_BLOCK_CHARS
    code = "x = 1\n" * (MAX_BLOCK_CHARS * 3 // 6)  # ~3 блока
    blocks = _fallback_blocks(code, "")
    assert len(blocks) >= 2
    for b in blocks:
        assert len(b["code"]) <= MAX_BLOCK_CHARS


def test_estimate_audit_minutes():
    """Оценка времени: 1 блок ~4-5 мин, больше блоков — больше."""
    from app.orchestrator import estimate_audit_minutes
    small = estimate_audit_minutes(5000)   # 1 блок
    large = estimate_audit_minutes(50000)  # ~4 блока
    assert small >= 2
    assert large > small


def test_max_blocks_limit():
    """MAX_BLOCKS = 16 — лимит зафиксирован."""
    from app.orchestrator import MAX_BLOCKS
    assert MAX_BLOCKS == 16


def test_chunker_still_works():
    """Старый chunker.py всё ещё работает (fallback)."""
    from app.chunker import split_code
    code = "def foo():\n    return 42\n"
    blocks = split_code(code)
    assert len(blocks) == 1


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
