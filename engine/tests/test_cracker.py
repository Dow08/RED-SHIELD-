"""Tests du cracker de hash (dictionnaire)."""
import binascii
import hashlib

from app.core.bus import EventBus
from app.modules.cracker import CrackerModule, CrackRequest


def test_crack_md5_finds_password():
    mod = CrackerModule(EventBus())
    mod.start()
    target = hashlib.md5(b"password").hexdigest()
    res = mod.crack(CrackRequest(algo="md5", target=target, words=["admin", "root", "password", "123456"]))
    assert res.found == "password"
    assert res.tried == 3


def test_crack_pbkdf2_roundtrip():
    mod = CrackerModule(EventBus())
    mod.start()
    salt = b"s3l"
    digest = binascii.hexlify(hashlib.pbkdf2_hmac("sha256", b"hunter2", salt, 50000, 32)).decode()
    res = mod.crack(CrackRequest(algo="pbkdf2_sha256", target=digest, salt=salt.hex(),
                                 iterations=50000, dklen=32, words=["letmein", "hunter2", "qwerty"]))
    assert res.found == "hunter2"


def test_crack_not_found():
    mod = CrackerModule(EventBus())
    mod.start()
    res = mod.crack(CrackRequest(algo="sha256", target="deadbeef", words=["a", "b"]))
    assert res.found is None and res.tried == 2


def test_crack_rejects_bad_algo():
    mod = CrackerModule(EventBus())
    mod.start()
    res = mod.crack(CrackRequest(algo="rot13", target="x", words=["a"]))
    assert res.error is not None
