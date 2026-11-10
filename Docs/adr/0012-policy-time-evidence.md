# Preserve policy timing uncertainty

The manifest now optionally records policy_snapshot_utc and policy_change_observed. Null means
unknown; absence of change evidence must not be silently converted to false. These are captured
facts, not an instruction or a new operator approval. Existing schema1.0 inputs remain readable.

The deterministic engine uses a120-second freshness ceiling, aligned with the per-collection
operation budget, and requires source windows to contain the event and policy snapshot. This
is an initial conservative engineering threshold, not a native validation result. It does not
prove historical continuity. A documented change or unknown continuity withholds proposals.
Current policy matching alone receives supported/unknown grades and explicit limitations;
historical confirmation is never inferred just from a nearby timestamp.

Collectors must leave change observation unknown unless actual source evidence establishes it.
Native captures and controlled before/after scenarios remain required at P13/G2/G3. If collection
cannot establish continuity, a refusal is the correct result. Do not add a checkbox that treats
operator intent as historical-policy proof. This ADR adds no policy write or collection source.
