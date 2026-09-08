from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import AliasChoices, model_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource

from app.core.settings.app import AppSettingsMixin
from app.core.settings.auth import AuthSettingsMixin
from app.core.settings.database import DatabaseSettingsMixin
from app.core.settings.local_auth import LocalAuthSettingsMixin
from app.core.settings.metrics import MetricsSettingsMixin
from app.core.settings.network import NetworkSettingsMixin
from app.core.settings.outbound import OutboundSettingsMixin
from app.core.settings.protocol_guard import ProtocolGuardSettingsMixin
from app.core.settings.redis import RedisSettingsMixin
from app.core.settings.scheduler import SchedulerSettingsMixin
from app.core.settings.session import SessionSettingsMixin


def _lookup_raw_value(data: dict[str, Any], *keys: str) -> tuple[bool, Any]:
    for key in keys:
        if key in data:
            return True, data[key]
    return False, None


def _normalize_alias_keys_for_settings(
    settings_cls: type[BaseSettings],
    data: dict[str, Any],
) -> dict[str, Any]:
    normalized = dict(data)
    for field_name, field_info in settings_cls.model_fields.items():
        validation_alias = field_info.validation_alias
        if isinstance(validation_alias, AliasChoices):
            aliases = [str(choice) for choice in validation_alias.choices]
        elif isinstance(validation_alias, str):
            aliases = [validation_alias]
        else:
            aliases = []

        for alias in aliases:
            if alias in normalized and field_name not in normalized:
                normalized[field_name] = normalized[alias]
            if alias != field_name:
                normalized.pop(alias, None)
    return normalized


def _read_secret_value(file_env_name: str, raw_path: Any) -> str:
    path = Path(str(raw_path)).expanduser()
    try:
        value = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValueError(f"{file_env_name} points to a missing file: {path}") from exc
    except PermissionError as exc:
        raise ValueError(f"{file_env_name} is not readable: {path}") from exc
    except OSError as exc:
        raise ValueError(f"{file_env_name} could not be read: {path} ({exc})") from exc

    if value.endswith("\n"):
        value = value[:-1]
        if value.endswith("\r"):
            value = value[:-1]
    if value == "":
        raise ValueError(f"{file_env_name} must not point to an empty file: {path}")
    return value


class Settings(
    LocalAuthSettingsMixin,
    SchedulerSettingsMixin,
    ProtocolGuardSettingsMixin,
    MetricsSettingsMixin,
    RedisSettingsMixin,
    NetworkSettingsMixin,
    AuthSettingsMixin,
    DatabaseSettingsMixin,
    SessionSettingsMixin,
    OutboundSettingsMixin,
    AppSettingsMixin,
    BaseSettings,
):
    """Application settings loaded from flat environment variables."""

    @model_validator(mode="before")
    @classmethod
    def _resolve_file_backed_settings(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        resolved = dict(data)
        mappings = (
            ("database_url", "DATABASE_URL", "database_url_file", "DATABASE_URL_FILE"),
            ("secret_key", "SECRET_KEY", "secret_key_file", "SECRET_KEY_FILE"),
            (
                "entra_client_secret",
                "ENTRA_CLIENT_SECRET",
                "entra_client_secret_file",
                "ENTRA_CLIENT_SECRET_FILE",
            ),
            (
                "entra_client_certificate_private_key",
                "ENTRA_CLIENT_CERTIFICATE_PRIVATE_KEY",
                "entra_client_certificate_private_key_file",
                "ENTRA_CLIENT_CERTIFICATE_PRIVATE_KEY_FILE",
            ),
            ("redis_url", "REDIS_URL", "redis_url_file", "REDIS_URL_FILE"),
        )

        for field_name, env_name, file_field_name, file_env_name in mappings:
            value_found, _ = _lookup_raw_value(resolved, field_name, env_name)
            file_found, file_path = _lookup_raw_value(resolved, file_field_name, file_env_name)
            if value_found and file_found:
                raise ValueError(f"{env_name} and {file_env_name} cannot both be set")
            if not file_found:
                continue
            resolved[field_name] = _read_secret_value(file_env_name, file_path)
            resolved[file_field_name] = str(file_path)

        return resolved

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        class _NormalizedAliasSource(PydanticBaseSettingsSource):
            def __init__(self, wrapped: PydanticBaseSettingsSource):
                super().__init__(wrapped.settings_cls)
                self._wrapped = wrapped

            def get_field_value(self, field, field_name):
                return self._wrapped.get_field_value(field, field_name)

            def __call__(self) -> dict[str, Any]:
                data = self._wrapped()
                return _normalize_alias_keys_for_settings(settings_cls, data)

        return (
            init_settings,
            _NormalizedAliasSource(env_settings),
            _NormalizedAliasSource(dotenv_settings),
            file_secret_settings,
        )

    model_config = {
        "env_file": ".env",
        "populate_by_name": True,
        "extra": "forbid",
    }


@lru_cache
def get_settings() -> Settings:
    return Settings()
