from blockchain_demo.crypto import KeyPair, canonical, hash_obj, verify


def test_sign_verify_roundtrip():
    key = KeyPair.generate()
    sig = key.sign(b"hello")
    assert verify(key.public_hex, b"hello", sig)
    assert not verify(key.public_hex, b"goodbye", sig)


def test_key_serialization():
    key = KeyPair.generate()
    clone = KeyPair.from_dict(key.to_dict())
    assert clone.public_hex == key.public_hex
    assert clone.secret_hex == key.secret_hex


def test_canonical_is_deterministic():
    a = {"b": 1, "a": [3, 2, 1], "c": {"y": 2, "x": 1}}
    b = {"c": {"x": 1, "y": 2}, "a": [3, 2, 1], "b": 1}
    assert canonical(a) == canonical(b)
    assert hash_obj(a) == hash_obj(b)
