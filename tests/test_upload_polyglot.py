import pytest
import security.upload_polyglot as mod

CASES = [
    ("magic_bytes", (1, 2)),
    ("content_type_check", (1, 2)),
    ("reencode_image", (1, 2)),
    ("exec_isolation", (1, 2)),
    ("extension_allowlist", (1, 2)),
    ("filename_sanitize", (1, 2)),
    ("polyglot_detect", (1, 2)),
    ("storage_partition", (1, 2)),
    ("size_limit", (1, 2)),
    ("validation", (1, 2)),
    ("audit", (1, 2)),
    ("error_map", (1, 2)),
    ("antivirus_hook", (1, 2)),
    ("versioning", (1, 2)),
    ("cleanup", (1, 2)),
]

@pytest.mark.parametrize("fn_name,args", CASES)
def test_contract(fn_name, args):
    fn = getattr(mod, fn_name)
    assert fn(*args) is not None
