from blockchain_demo.crypto import (
    AccountKey,
    KeyPair,
    _der_decode_ints,
    address_from_pubkey,
    canonical,
    hash_obj,
    verify,
    verify_ecdsa,
    SECP256K1_N,
)


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


# ----------------------------------------------------- ECDSA account keys
def test_ecdsa_sign_verify_roundtrip():
    key = AccountKey.generate()
    sig = key.sign(b"transfer-body")
    assert verify_ecdsa(key.public_hex, b"transfer-body", sig)
    # wrong message / wrong key must both fail
    assert not verify_ecdsa(key.public_hex, b"other-body", sig)
    other = AccountKey.generate()
    assert not verify_ecdsa(other.public_hex, b"transfer-body", sig)


def test_ecdsa_signatures_are_low_s():
    """Every produced signature must satisfy the low-S (malleability) rule."""
    key = AccountKey.generate()
    for i in range(20):
        _, s = _der_decode_ints(bytes.fromhex(key.sign(f"msg-{i}".encode())))
        assert 0 < s <= SECP256K1_N // 2


def test_ecdsa_high_s_signature_rejected():
    """A malleated high-S counterpart of a valid signature must not verify."""
    from blockchain_demo.crypto import _der_encode_ints

    key = AccountKey.generate()
    msg = b"malleable"
    r, s = _der_decode_ints(bytes.fromhex(key.sign(msg)))
    high_s = SECP256K1_N - s  # the other valid s for the same (r, z, key)
    assert high_s > SECP256K1_N // 2
    # cryptography accepts high-S on verify; our wrapper must reject it.
    assert not verify_ecdsa(key.public_hex, msg, _der_encode_ints(r, high_s).hex())


def test_account_address_derived_from_pubkey():
    key = AccountKey.generate()
    assert key.address == address_from_pubkey(key.public_hex)
    assert len(key.address) == 40  # 20 bytes hex
    # address is NOT the raw public key (unlike validator keys)
    assert key.address != key.public_hex


def test_account_key_serialization_roundtrip():
    key = AccountKey.generate()
    clone = AccountKey.from_dict(key.to_dict())
    assert clone.address == key.address
    assert clone.public_hex == key.public_hex
    assert clone.secret_hex == key.secret_hex
    # a key restored from disk signs transactions that verify
    sig = clone.sign(b"x")
    assert verify_ecdsa(key.public_hex, b"x", sig)


def test_distinct_accounts_have_distinct_addresses():
    addresses = {AccountKey.generate().address for _ in range(20)}
    assert len(addresses) == 20


def test_ecdsa_rejects_garbage():
    key = AccountKey.generate()
    assert not verify_ecdsa("not-hex", b"m", key.sign(b"m"))
    assert not verify_ecdsa(key.public_hex, b"m", "not-hex")
    assert not verify_ecdsa("00" * 65, b"m", "00")

