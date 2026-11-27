# 🔐 CryptoVault

Bibliothèque de cryptographie en Python, construite étape par étape dans un but pédagogique (ENSA Agadir – SITCN).

> ⚠️ Projet éducatif : ne pas utiliser en production.

## Avancement

| Module | Contenu | Statut |
|---|---|---|
| `src/classical.py` | César, Vigenère, XOR | ✅ |
| `src/symmetric.py` | AES-256-GCM | ✅ |
| `src/asymmetric.py` | RSA-OAEP, signature et Diffie–Hellman avec HKDF | ✅ |
| `src/hashing.py` | SHA-256, bcrypt et vérification HMAC avec `compare_digest` | ✅ |
| `src/pki.py` | Autorité racine X.509 et certificats serveur et client | ✅ |
| `src/messaging.py`, `messenger/` | Chiffrement hybride et relais Flask local | ✅ |
| `src/secrets_mgr.py` | Coffre chiffré, rotation des secrets et audit | ✅ |

## Installation

```bash
git clone https://github.com/secboy-star/cryptovault.git
cd cryptovault
python -m venv crypto_env
source crypto_env/bin/activate      # Linux/macOS
crypto_env\Scripts\activate        # Windows
pip install -r requirements.txt
```

## Utilisation

```bash
python -m src.classical    # César, Vigenère, XOR
python -m src.symmetric    # AES-256-GCM
python -m unittest discover -s tests -v
python -m src.messaging    # Chiffrement puis déchiffrement local
python -m flask --app messenger.app run --host 127.0.0.1
```

Le relais local reçoit et renvoie les enveloppes chiffrées avec `POST` et `GET` sur `/inbox/<destinataire>`. Les clients utilisent `encrypt_message()` et `decrypt_message()` de `src.messaging` et gardent leurs clés privées.

Pour la PKI, `create_ca()` crée une racine en mémoire. `issue_certificate()` émet un certificat client par défaut, ou serveur avec `is_server=True`.

```python
from getpass import getpass
from src.secrets_mgr import SecretVault

vault = SecretVault(getpass("Mot de passe du coffre de démo : "))
vault.store("demo", "valeur fictive")
vault.rotate("demo", "nouvelle valeur fictive")
assert vault.get("demo") == "nouvelle valeur fictive"
print(vault.audit_log())
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
