# PROMPT 4 — Le SaaS "Ship-It" Public (auth + paiement + IA + deploy)

**Quand l'utiliser** : tu veux lancer un vrai SaaS public monétisable, du concept à la mise en ligne.

---

Objectif : construire et déployer une app SaaS publique, de l'idée à la mise en ligne.

## Concept
[ Décrire l'app — ex : "un outil qui génère du contenu social à partir de mes écrits" ]

## Fonctionnalités requises
1. Authentification (Google + email/mot de passe)
2. Intégration Stripe (abonnement / paiement)
3. Génération de contenu par IA (API Claude ou OpenAI)
4. Base de données (utilisateurs + contenu généré)
5. Dashboard admin (vue utilisateurs, gestion des invitations)

## Processus obligatoire
1. Brainstorm : pose-moi 5-8 questions pour clarifier périmètre, tarification, persona, edge cases (échec paiement, quota IA, désinscription). Attends mes réponses.
2. `spec.md` (exigences + stack + modèle de données + 3 milestones)
3. Scaffold : structure de fichiers, config, variables d'env documentées dans `.env.example`
4. Implémentation jalon par jalon (frontend mocké d'abord, puis backend, puis branchement réel)
5. Tests (auth, paiement, IA, edge cases)
6. Sécurité : revue (secrets, validation, rate limiting, headers de sécurité, protection CSRF/XSS)
7. Déploiement public (Vercel/Netlify + base managée) — guide pas à pas
8. Checklist de pré-déploiement + stratégie de rollback

## Règles
- Code complet, gestion d'erreurs, états de chargement, fallbacks (ex : si l'API IA tombe)
- Aucun secret en dur ; tout via variables d'environnement
- Valide avec moi avant tout déploiement et avant d'activer des paiements réels
- Auto-vérification finale : l'app démarre-t-elle ? Les paiements sont-ils en mode test ? Les tests passent-ils ? Corrige si non.
