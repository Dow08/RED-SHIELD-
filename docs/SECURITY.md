# Politique de sécurité

RED SHIELD est un outil de sécurité réseau (observation + reconnaissance). La
sécurité du projet lui-même est prise au sérieux.

## Signaler une vulnérabilité

**Ne pas ouvrir d'issue publique** pour une faille de sécurité.

Utilisez le canal privé de GitHub : onglet **Security → Report a vulnerability**
(GitHub Security Advisories). Le rapport reste confidentiel jusqu'à correction.

Merci d'inclure :

- une description de la faille et de son impact ;
- les étapes de reproduction (proof of concept si possible) ;
- la version / le commit concerné.

Délai de première réponse visé : **7 jours**.

## Périmètre

Sont dans le périmètre : le moteur Python (`engine/`), l'interface (`ui/`), le
plugin recon natif (`ui/src-tauri/`) et les workflows CI (`.github/`).

Rappel d'usage : RED SHIELD réalise du **scan actif**. Il ne doit être utilisé que
sur des systèmes dont vous êtes propriétaire ou pour lesquels vous disposez d'une
**autorisation écrite** (voir [`MANDAT-AUTORISATION.md`](MANDAT-AUTORISATION.md)).
L'usage non autorisé est illégal et n'engage que l'utilisateur.

## Versions supportées

Le projet est en développement actif ; seule la dernière version publiée sur
`main` reçoit des correctifs de sécurité.
