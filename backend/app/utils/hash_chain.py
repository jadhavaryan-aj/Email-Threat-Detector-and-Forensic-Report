"""SHA-256 hash-chained, append-only evidence log primitives. Tamper-evident:
modifying any past entry's stored payload changes what its hash *should* be,
breaking the link to every entry chained after it. verify_chain() genuinely
recomputes every hash from the stored payload on each call — it's a live check,
not a cached flag that could go stale or be spoofed."""

import hashlib
import json

GENESIS_HASH = "genesis"


def compute_entry_hash(prev_hash: str, payload: dict) -> str:
    # sort_keys makes this deterministic regardless of dict insertion order;
    # default=str covers datetimes/etc. that might end up in a payload.
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(f"{prev_hash}|{canonical}".encode("utf-8")).hexdigest()


def verify_chain(entries: list[dict]) -> tuple[bool, int | None]:
    """entries must be in chain order (oldest first), each a dict with
    prev_entry_hash, entry_hash, and payload. Returns (valid, first_broken_index)."""
    prev_hash = GENESIS_HASH
    for index, entry in enumerate(entries):
        if entry["prev_entry_hash"] != prev_hash:
            return False, index
        if compute_entry_hash(prev_hash, entry["payload"]) != entry["entry_hash"]:
            return False, index
        prev_hash = entry["entry_hash"]
    return True, None
