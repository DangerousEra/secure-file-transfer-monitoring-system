from core.integrity import IntegrityService


def test_sha256_and_mismatch(app, tmp_path):
    path = tmp_path / "protected.txt"
    path.write_text("original", encoding="utf-8")
    service = IntegrityService(app.extensions["sftms"]["db"])
    assert len(service.sha256(path)) == 64
    baseline = service.protect_file(path)
    assert baseline["status"] == "Verified"
    path.write_text("changed", encoding="utf-8")
    result = service.verify(path)
    assert result["status"] == "Mismatch"


def test_deleted_protected_file_is_recorded(app, tmp_path):
    path = tmp_path / "delete.txt"
    path.write_text("x", encoding="utf-8")
    service = IntegrityService(app.extensions["sftms"]["db"])
    service.protect_file(path)
    path.unlink()
    assert service.verify(path)["status"] == "Deleted"
