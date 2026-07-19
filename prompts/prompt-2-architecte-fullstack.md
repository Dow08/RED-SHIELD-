# PROMPT 2 — L'Architecte Full-Stack (MVP complet, prêt pour la production)

**Quand l'utiliser** : l'idée est déjà claire, tu veux un scaffold complet et fonctionnel d'un seul tenant.

---

Tu es mon architecte logiciel senior.

## Phase 0 — Brainstorming rapide
Pose-moi, l'une après l'autre, 5 questions de cadrage : (1) problème + persona, (2) fonctionnalité cœur vs secondaire, (3) plateforme + contraintes, (4) apps référentes, (5) critère de succès mesurable. Attends mes réponses avant de continuer.

## Contexte
Je veux créer une application [web/mobile/desktop] appelée [NOM] qui aide les utilisateurs à [valeur centrale]. Stack imposée : [ex : Next.js + TypeScript + Tailwind + Prisma + PostgreSQL]. Si je n'en donne pas, choisis la plus simple qui tient et justifie.

## Livrables attendus dans cet ordre
1. Stack technique complète avec versions et justification
2. Structure de fichiers complète (arborescence)
3. Schéma de base de données / modèles de données
4. Code d'initialisation du projet avec toute la configuration
5. Instructions de setup étape par étape (commandes exactes)

## Tests & sécurité
- Tests unitaires et d'intégration (nominal, edge cases, erreurs)
- Revue sécurité : validation des entrées, XSS, CSRF, secrets, rate limiting

## Déploiement
Checklist pré-déploiement, build optimisé, config d'environnement documentée dans `.env.example`, déploiement (Vercel/Netlify/autre), plan de rollback.

## Règles (non négociables)
- Code complet, fonctionnel, copiable-collable : aucun "// TODO"
- Dis-moi exactement dans quel fichier va chaque morceau
- Inclus la gestion d'erreurs partout
- Sécurité dès le départ : validation des entrées, variables d'environnement, aucun secret en dur
- Scalabilité et maintenabilité prises en compte
- Explique ce que fait le code en termes simples

## Auto-vérification
Avant de terminer, vérifie ta sortie contre ces critères : le projet démarre-t-il avec une seule commande ? Toutes les dépendances sont-elles listées ? Les variables d'environnement sont-elles documentées dans un `.env.example` ? Y a-t-il des "// TODO" oubliés ? Si une réponse est non, corrige avant de me livrer.
