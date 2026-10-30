# 🔐 CryptoVault

Bibliothèque de cryptographie en Python, construite étape par étape dans un but pédagogique (ENSA Agadir – SITCN).

> ⚠️ Projet éducatif : ne pas utiliser en production.

## Avancement

| Module | Contenu | Statut |
|---|---|---|
| `src/classical.py` | César, Vigenère, XOR | ✅ |
| `src/symmetric.py` | AES-256-GCM | ✅ |
| `src/asymmetric.py` | RSA-OAEP, signature, Diffie-Hellman | 🔜 |
| `src/hashing.py` | SHA-256, bcrypt, HMAC | 🔜 |
| `src/pki.py` | Autorité de certification X.509 | 🔜 |
| `messenger/` | Messagerie chiffrée E2E (Flask) | 🔜 |
| `src/secrets_mgr.py` | Gestionnaire de secrets avec rotation et audit | 🔜 |

## Installation

```bash
git clone https://github.com/secboy-star/cryptovault.git
cd cryptovault
python -m venv crypto_env
crypto_env\Scripts\activate        # Windows
pip install -r requirements.txt
```

## Utilisation

```bash
python -m src.classical    # César, Vigenère, XOR
python -m src.symmetric    # AES-256-GCM
```

## Ce que j'ai appris (bugs réels)

- **César + « ö »** : `isalpha()` accepte les lettres accentuées, mais le modulo 26 suppose A-Z → chiffrement non réversible. Corrigé en restreignant aux lettres ASCII.
- **Vigenère + clé « key1 »** : le « 1 » se comportait comme un « K » (shift -16 mod 26 = 10) → deux clés différentes donnaient le même chiffré. Corrigé par une validation de la clé.
- **XOR vs AES-GCM** : un seul bit modifié n'est pas détecté avec XOR, alors que AES-GCM lève `MAC check failed`.

## Transparence sur l'usage de l'IA

J'utilise Claude (Anthropic) comme tuteur : il m'explique le code ligne par ligne. J'écris, je teste et je modifie le code moi-même, et je documente mes erreurs dans le compte rendu (`docs/`).

## Documentation

Compte rendu détaillé et captures d'écran : dossier [`docs/`](docs/).

## Sécurité

Aucune clé privée n'est versionnée (`*.pem` et `vault.enc` sont dans `.gitignore`).

## Licence

MIT
