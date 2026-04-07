import keyring
import os

SERVICE_NAME = "VirusTotalScanner"
API_KEY_ENTRY = "vt_api_key"


class ApiKeyManager:
    @staticmethod
    def save_api_key(api_key: str) -> None:
        if not api_key or not api_key.strip():
            raise ValueError("API key cannot be empty")
        
        keyring.set_password(SERVICE_NAME, API_KEY_ENTRY, api_key.strip())
        
        config_dir = os.path.expanduser("~/.config/virus_total_scanner")
        os.makedirs(config_dir, exist_ok=True)
        os.chmod(config_dir, 0o700)

    @staticmethod
    def get_api_key() -> str | None:
        return keyring.get_password(SERVICE_NAME, API_KEY_ENTRY)

    @staticmethod
    def delete_api_key() -> None:
        keyring.delete_password(SERVICE_NAME, API_KEY_ENTRY)

    @staticmethod
    def has_api_key() -> bool:
        return ApiKeyManager.get_api_key() is not None
