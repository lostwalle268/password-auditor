from utils import estimate_entropy

def test_entropy_empty():
    assert estimate_entropy("") == 0.0

def test_entropy_letters():
    e = estimate_entropy("abcd")
    assert e > 0
