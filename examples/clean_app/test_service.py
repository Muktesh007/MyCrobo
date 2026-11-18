from service import digest


def test_digest_length():
    assert len(digest(b"x")) == 64
