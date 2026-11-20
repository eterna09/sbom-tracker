from app.auth.passwords import hash_password, verify_password


def test_hash_does_not_contain_the_plain_password() -> None:
    hashed = hash_password("correct horse battery staple")

    assert "correct horse battery staple" not in hashed


def test_verify_accepts_the_correct_password() -> None:
    hashed = hash_password("correct horse battery staple")

    assert verify_password("correct horse battery staple", hashed)


def test_verify_rejects_a_wrong_password() -> None:
    hashed = hash_password("correct horse battery staple")

    assert not verify_password("wrong password", hashed)


def test_same_password_produces_different_hashes() -> None:
    assert hash_password("same password") != hash_password("same password")


def test_verify_rejects_a_malformed_hash() -> None:
    assert not verify_password("anything", "not-a-real-hash")
