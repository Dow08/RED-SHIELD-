"""Module Offensif — cracker de hash par dictionnaire (repris de sk-security-toolkit).

Pur Python (hashlib), 100 % local, aucune dépendance externe. Usage CTF / pentest
autorisé : l'utilisateur fournit le hash cible, les paramètres et sa propre wordlist.
"""
from __future__ import annotations

import binascii
import hashlib

from pydantic import BaseModel

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus

_MAX_WORDS = 200_000
_MAX_ITER = 2_000_000
ALGOS = ("pbkdf2_sha256", "pbkdf2_sha512", "md5", "sha1", "sha256", "sha512")


class CrackRequest(BaseModel):
    algo: str = "pbkdf2_sha256"
    target: str  # digest cible (hex)
    salt: str = ""  # hex, sinon interprété en texte
    iterations: int = 100_000
    dklen: int = 32
    words: list[str] = []


class CrackResult(BaseModel):
    found: str | None = None
    tried: int = 0
    algo: str = ""
    error: str | None = None


class CrackerModule(Module):
    name = "cracker"
    version = "0.1.0"
    description = "Cracker de hash (dictionnaire) — CTF/pentest autorisé"
    produces = ["crack"]

    def __init__(self, bus: EventBus) -> None:
        super().__init__(bus)

    def start(self) -> None:
        self.set_status(ModuleStatus.ACTIVE)

    @staticmethod
    def _salt_bytes(salt: str) -> bytes:
        if not salt:
            return b""
        try:
            return binascii.unhexlify(salt)
        except (binascii.Error, ValueError):
            return salt.encode()

    def _digest(self, algo: str, word: str, salt: bytes, iters: int, dklen: int) -> str:
        wb = word.encode("utf-8", "ignore")
        if algo == "pbkdf2_sha256":
            return binascii.hexlify(hashlib.pbkdf2_hmac("sha256", wb, salt, iters, dklen)).decode()
        if algo == "pbkdf2_sha512":
            return binascii.hexlify(hashlib.pbkdf2_hmac("sha512", wb, salt, iters, dklen)).decode()
        if algo in ("md5", "sha1", "sha256", "sha512"):
            h = hashlib.new(algo)
            h.update(salt + wb if salt else wb)
            return h.hexdigest()
        return ""

    def crack(self, req: CrackRequest) -> CrackResult:
        if req.algo not in ALGOS:
            return CrackResult(algo=req.algo, error=f"algo inconnu (choix : {', '.join(ALGOS)})")
        if req.iterations > _MAX_ITER:
            return CrackResult(algo=req.algo, error=f"iterations trop élevé (max {_MAX_ITER})")
        target = req.target.strip().lower()
        if not target:
            return CrackResult(algo=req.algo, error="hash cible manquant")
        salt = self._salt_bytes(req.salt)
        iters = max(1, req.iterations)
        dklen = max(1, min(req.dklen, 512))
        tried = 0
        for raw in req.words[:_MAX_WORDS]:
            word = raw.rstrip("\r\n")
            if not word:
                continue
            tried += 1
            if self._digest(req.algo, word, salt, iters, dklen) == target:
                return CrackResult(found=word, tried=tried, algo=req.algo)
        return CrackResult(found=None, tried=tried, algo=req.algo)
