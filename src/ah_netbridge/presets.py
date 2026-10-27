"""Strict schema-versioned radio preset loading."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .native import (
    BANDWIDTHS_MHZ, CHANNEL_MAX_KHZ, CHANNEL_MIN_KHZ, MAX_CHANNELS, TX_POWER_MAX_DBM,
    TX_POWER_MIN_DBM, valid_channel_khz,
)


class PresetError(ValueError):
    pass


@dataclass(frozen=True)
class RadioPreset:
    id: str
    name: str
    description: str
    jurisdiction: str
    source_url: str
    warning: str
    channels_khz: tuple[int, ...]
    bandwidth_mhz: int
    tx_power_dbm: int


REQUIRED = {
    "schema_version", "id", "name", "description", "jurisdiction",
    "source_url", "warning", "channels_khz", "bandwidth_mhz", "tx_power_dbm",
}


def validate_preset(data: dict[str, object], source: str = "preset") -> RadioPreset:
    if set(data) != REQUIRED:
        raise PresetError(f"{source}: fields must exactly match schema version 1")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise PresetError(f"{source}: unsupported schema version")
    strings = ("id", "name", "description", "jurisdiction", "source_url", "warning")
    if any(type(data[key]) is not str or not str(data[key]).strip() for key in strings):
        raise PresetError(f"{source}: text fields must be non-empty strings")
    identifier = str(data["id"])
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", identifier):
        raise PresetError(f"{source}: id must use lowercase ASCII, digits, '-' or '_'")
    url = urlparse(str(data["source_url"]))
    if url.scheme not in {"http", "https"} or not url.netloc:
        raise PresetError(f"{source}: source_url must be an absolute HTTP(S) URL")
    channels = data["channels_khz"]
    if type(channels) is not list or not 1 <= len(channels) <= MAX_CHANNELS:
        raise PresetError(f"{source}: channels_khz must contain 1–{MAX_CHANNELS} values")
    for value in channels:
        if not valid_channel_khz(value):
            raise PresetError(
                f"{source}: channels must be {CHANNEL_MIN_KHZ}–{CHANNEL_MAX_KHZ} kHz "
                "with exact 0.1 MHz resolution"
            )
    if len(set(channels)) != len(channels):
        raise PresetError(f"{source}: channels must not be duplicated")
    bandwidth = data["bandwidth_mhz"]
    power = data["tx_power_dbm"]
    if type(bandwidth) is not int or bandwidth not in BANDWIDTHS_MHZ:
        raise PresetError(f"{source}: bandwidth_mhz must be 1, 2, 4 or 8")
    if type(power) is not int or not TX_POWER_MIN_DBM <= power <= TX_POWER_MAX_DBM:
        raise PresetError(f"{source}: tx_power_dbm must be {TX_POWER_MIN_DBM}–{TX_POWER_MAX_DBM}")
    return RadioPreset(
        identifier, str(data["name"]), str(data["description"]),
        str(data["jurisdiction"]), str(data["source_url"]), str(data["warning"]),
        tuple(channels), bandwidth, power,
    )


def load_presets(directory: Path) -> list[RadioPreset]:
    if not directory.exists():
        return []
    profiles: list[RadioPreset] = []
    ids: set[str] = set()
    for path in sorted(directory.glob("*.toml")):
        try:
            with path.open("rb") as stream:
                profile = validate_preset(tomllib.load(stream), path.name)
        except tomllib.TOMLDecodeError as error:
            raise PresetError(f"{path.name}: invalid TOML") from error
        except OSError as error:
            raise PresetError(f"{path.name}: could not be read ({error.strerror})") from error
        if profile.id in ids:
            raise PresetError(f"{path.name}: duplicate preset id '{profile.id}'")
        ids.add(profile.id)
        profiles.append(profile)
    return profiles
