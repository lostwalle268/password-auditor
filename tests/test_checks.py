from auditor import analyze_password

def test_common_password():
    wl = {"123456", "password"}
    r = analyze_password("password", wl)
    assert r['is_common'] is True
