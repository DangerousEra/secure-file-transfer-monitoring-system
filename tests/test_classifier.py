from core.classifier import FileClassifier


def test_sensitive_extension_is_classified():
    classifier = FileClassifier()
    result = classifier.classify("C:/demo/credential.key")
    assert result["sensitive"] is True
    assert result["risk_level"] == "High"


def test_normal_extension_is_not_sensitive():
    assert FileClassifier().classify("C:/demo/notes.txt")["classification"] == "Normal"
