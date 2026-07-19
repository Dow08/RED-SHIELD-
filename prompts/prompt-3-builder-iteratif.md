# PROMPT 3 — Le Builder Itératif (Spec → Todo → Code, mode plan, commit par feature)

**Quand l'utiliser** : tu veux construire progressivement, en gardant le contrôle à chaque étape et un historique git propre.

---

On construit [DESCRIPTION DE L'APP] de A à Z, jalon par jalon. Procède ainsi :

## Phase 0 — Exploration & cadrage
Commence en MODE PLAN (ne code rien). Pose-moi d'abord 5 questions de cadrage sur le problème, le persona, la fonctionnalité cœur, les contraintes et les critères de succès. Attends mes réponses. Ensuite explique l'état du codebase (ou son absence), puis propose 2-3 solutions en partant de la plus simple. Attends que je choisisse.

## Phase 1 — Spec
Crée `spec.md` : exigences, stack technique, guidelines de design, et jusqu'à 3 milestones.

## Phase 2 — Todo du jalon 1
Crée `todo.md` : liste de tâches ordonnée et cochable pour le milestone 1.

## Phase 3 — Code incrémental
Exécute le todo une tâche à la fois. Après chaque tâche complète :
- Vérifie que ça compile et/ou que les tests passent
- Commit git avec un message clair décrivant la tâche
- Coche la case dans `todo.md`
- Attends mon "continue" avant la tâche suivante

## Phase 4 — Tests & polish
Pour chaque feature : tests (cas nominaux, edge cases, erreurs), accessibilité, responsive.

## Phase 5 — Déploiement
Checklist pré-déploiement, build optimisé, config d'environnement, déploiement (Vercel/Netlify/autre), monitoring, rollback.

## Règles
- Toujours commencer en mode plan ; si tu veux coder, je te stoppe
- Si tu rencontres un bug : utilise "think ultra hard", lis les logs console, propose la cause racine avant le correctif
- Une seule feature par branche / session
- Demande confirmation avant toute action irréversible (suppression, déploiement, migration de base)
- Crée un fichier `CLAUDE.md` capturant préférences, stack et conventions pour les sessions suivantes
