import os


VAULT_ADDR: str = os.environ.get("VAULT_ADDR", "http://localhost:8200")
VAULT_TOKEN: str = os.environ.get("VAULT_TOKEN", "")
VAULT_KEY_PREFIX: str = "tenant-"
VAULT_MOUNT: str = "transit"
DATABASE_URL: str = os.environ.get("DATABASE_URL", "sqlite:///./vault_pro.db")

# Internal service-to-service API key (required)
API_KEY: str = os.environ.get("VAULT_PRO_API_KEY", "")
