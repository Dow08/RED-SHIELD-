"""Exécution de commandes système — point de passage unique et durci.

Toute la surface « lancer un processus externe » (nmap, netsh, arp, winget,
pktmon, PowerShell…) transite par ici. Règles appliquées de façon centralisée :

 - **jamais `shell=True`** : on ne passe qu'une liste d'arguments (pas d'injection
   shell possible, l'OS ne réinterprète pas la ligne) ;
 - **timeout obligatoire** : aucune commande ne peut bloquer le moteur ;
 - **aucune fenêtre console** (`CREATE_NO_WINDOW` sous Windows) : pas de clignotement
   ni de console détournable ;
 - **encodage tolérant** (utf-8 / errors=replace) et **erreurs isolées** : un
   exécutable manquant ou en échec renvoie proprement (ok=False), sans lever.
"""
from __future__ import annotations

import subprocess
import sys

# Constante Windows uniquement — 0 (neutre) ailleurs.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
# Alias public pour les cas Popen (flux temps réel, ex. pktmon) qui ne passent pas par run().
NO_WINDOW = _NO_WINDOW


def run(args, timeout: int = 20) -> tuple[bool, str, str]:
    """Exécute une commande passée en **liste d'arguments**. Renvoie (ok, stdout, stderr).

    `args` doit être une liste/tuple non vide de chaînes ; toute autre forme est
    refusée (défense en profondeur contre un appel `shell`).
    """
    if not isinstance(args, (list, tuple)) or not args or not all(isinstance(a, str) for a in args):
        return (False, "", "commande invalide")
    try:
        p = subprocess.run(
            list(args),
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace", creationflags=_NO_WINDOW,
        )
        return (p.returncode == 0, p.stdout or "", p.stderr or "")
    except FileNotFoundError:
        return (False, "", "exécutable introuvable")
    except subprocess.TimeoutExpired:
        return (False, "", "timeout")
    except Exception as exc:
        return (False, "", str(exc))


def powershell(script: str, timeout: int = 25) -> tuple[bool, str]:
    """Exécute un script PowerShell en lecture seule (-NoProfile -NonInteractive).

    Renvoie (ok, stdout). À réserver à des scripts **construits par le code**
    (jamais concaténés avec une entrée utilisateur brute)."""
    ok, out, _ = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=timeout)
    return (ok, out)
