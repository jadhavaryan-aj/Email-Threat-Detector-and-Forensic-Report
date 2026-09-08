from app.utils.hash_chain import GENESIS_HASH, compute_entry_hash, verify_chain


def _build_chain(payloads: list[dict]) -> list[dict]:
    entries = []
    prev_hash = GENESIS_HASH
    for payload in payloads:
        entry_hash = compute_entry_hash(prev_hash, payload)
        entries.append({"prev_entry_hash": prev_hash, "entry_hash": entry_hash, "payload": payload})
        prev_hash = entry_hash
    return entries


def test_compute_entry_hash_is_deterministic_regardless_of_key_order():
    a = compute_entry_hash("genesis", {"x": 1, "y": 2})
    b = compute_entry_hash("genesis", {"y": 2, "x": 1})
    assert a == b


def test_compute_entry_hash_changes_with_prev_hash():
    payload = {"action": "ingested"}
    assert compute_entry_hash("genesis", payload) != compute_entry_hash("some-other-hash", payload)


def test_verify_chain_accepts_untampered_chain():
    entries = _build_chain([{"a": 1}, {"b": 2}, {"c": 3}])
    valid, first_broken_index = verify_chain(entries)
    assert valid is True
    assert first_broken_index is None


def test_verify_chain_empty_chain_is_valid():
    assert verify_chain([]) == (True, None)


def test_verify_chain_detects_payload_tampering():
    entries = _build_chain([{"a": 1}, {"b": 2}, {"c": 3}])
    entries[1]["payload"] = {"b": 999}  # mutate a middle entry's payload only

    valid, first_broken_index = verify_chain(entries)
    assert valid is False
    assert first_broken_index == 1


def test_verify_chain_detects_reordered_entries():
    entries = _build_chain([{"a": 1}, {"b": 2}, {"c": 3}])
    entries[0], entries[1] = entries[1], entries[0]

    valid, first_broken_index = verify_chain(entries)
    assert valid is False
    assert first_broken_index == 0


def test_verify_chain_detects_truncated_prefix():
    """Deleting the genesis entry should be caught, not silently accepted as
    a valid shorter chain — the second entry's prev_entry_hash no longer
    equals GENESIS_HASH."""
    entries = _build_chain([{"a": 1}, {"b": 2}])
    truncated = entries[1:]

    valid, first_broken_index = verify_chain(truncated)
    assert valid is False
    assert first_broken_index == 0
