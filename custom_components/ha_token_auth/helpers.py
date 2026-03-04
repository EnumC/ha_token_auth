"""Helper functions for auth token config parsing."""

from __future__ import annotations

from collections.abc import Iterable
from collections.abc import Mapping


def normalize_allowlist(tokens: Iterable[str]) -> list[str]:
    """Normalize token list by trimming and de-duplicating in insertion order."""
    result: list[str] = []
    seen: set[str] = set()

    for token in tokens:
        value = token.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)

    return result


def _iter_token_user_pairs(
    token_user_map: Iterable[dict[str, str]] | Mapping[str, str],
) -> Iterable[tuple[str, str]]:
    """Yield token/user pairs from either dict or list storage formats."""
    if isinstance(token_user_map, Mapping):
        for token, user_id in token_user_map.items():
            yield str(token), str(user_id)
        return

    for entry in token_user_map:
        if not isinstance(entry, Mapping):
            continue
        token = entry.get("token")
        user_id = entry.get("user_id")
        if token is None or user_id is None:
            continue
        yield str(token), str(user_id)


def normalize_token_user_map(
    token_user_map: Iterable[dict[str, str]] | Mapping[str, str],
) -> list[dict[str, str]]:
    """Normalize token/user list by trimming and de-duplicating by token."""
    result: list[dict[str, str]] = []
    seen_tokens: set[str] = set()

    for token, user_id in _iter_token_user_pairs(token_user_map):
        clean_token = token.strip()
        clean_user_id = user_id.strip()
        if not clean_token or not clean_user_id or clean_token in seen_tokens:
            continue
        seen_tokens.add(clean_token)
        result.append({"token": clean_token, "user_id": clean_user_id})

    return result
