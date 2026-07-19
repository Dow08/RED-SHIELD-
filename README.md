# RED — Network Shield & Recon

Bouclier réseau modulaire **red + blue** : observe les connexions de ta machine en temps réel, les note, les explique et propose des remédiations priorisées — le tout dans un dashboard sombre moderne, extensible par modules.

> ⚠️ **Usage autorisé uniquement** : sur des machines/réseaux dont tu es propriétaire ou pour lesquels tu détiens une autorisation écrite (pentest, lab). Un disclaimer et un journal d'audit sont intégrés.

## État
🚧 En construction — **Jalon 1 (bouclier local)**. Voir [`project-plan.md`](project-plan.md), [`spec.md`](spec.md), [`analysis.md`](analysis.md).

## Stack
- **Moteur** : Python 3.11+ · FastAPI · psutil · SQLite
- **Frontend** : React + Vite + TypeScript + Tailwind
- Détail et conventions : [`CLAUDE.md`](CLAUDE.md)

## Prérequis
- **Python 3.11+** (testé 3.14 ; utiliser le lanceur `py` sous Windows)
- **Node.js 18+** (testé v24)
- **git**
- *(nmap : seulement pour le Jalon 3 — Recon)*

## Installation & lancement
> Instructions détaillées ajoutées au fur et à mesure des étapes du Jalon 1.

```bash
# Backend (moteur)
cd engine
py -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
py -m uvicorn app.main:app --reload

# Frontend (dashboard)
cd ui
npm install
npm run dev
```

Copier `.env.example` en `.env` avant le premier lancement.

## Principes
Zéro donnée inventée · mode air-gapped par défaut · architecture modulaire tolérante aux pannes · tout testé de bout en bout.
