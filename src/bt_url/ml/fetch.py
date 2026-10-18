"""`python -m bt_url.ml.fetch` : télécharge et vérifie (SHA256) le modèle — utilisé au build Docker."""

import sys

from bt_url.config import get_settings
from bt_url.ml.model import ModelIntegrityError, download_model


def main() -> int:
    s = get_settings()
    try:
        download_model(s.model_url, s.model_path, s.model_sha256, s.allow_unverified_model)
    except ModelIntegrityError as e:
        print(f"REFUSÉ : {e}", file=sys.stderr)
        return 1
    print(f"Modèle vérifié et enregistré : {s.model_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
