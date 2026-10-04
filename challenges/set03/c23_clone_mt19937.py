from itertools import islice

from cryptopals.mt import MersenneTwister, N, untemper

# seed for the twister we want to clone
INITIAL_SEED = 5487
# number of times to validate that cloned twister matches what we control
N_COMPARE = 2000


def clone(outputs: list[int]) -> MersenneTwister:
    """
    Create a new MT by reverse engineering the state from the outputs of an existing instance.

    Note: this assumes mt.N outputs, covering index 0..N.
    This will cause problems with a different length list, or
    if the samples are offset from the index.

    """
    if not len(outputs) == N:
        raise ValueError(f"Expects {N} values, got {len(outputs)}")
    # Undo the tempering of those values to recreate the state they were produced from
    recreated_state = [untemper(v) for v in outputs]
    # Now splice that (recreated) state into a brand new twister
    # (NB: seed doesn't matter here, because we're about to override the state)
    mt_new = MersenneTwister(0)
    mt_new.state = recreated_state
    return mt_new


if __name__ == "__main__":
    # Create a twister, and generate enough values to cause it to twist
    mt_old = MersenneTwister(INITIAL_SEED)
    values = list(islice(mt_old, N))

    # Clone mt_old from these output values
    mt_new = clone(values)

    # Ensure that we match the cloned output
    old = list(islice(mt_old, N_COMPARE))
    new = list(islice(mt_new, N_COMPARE))
    for i, (o, n) in enumerate(zip(old, new, strict=True)):
        assert o == n, f"index {i} mismatch {o} != {n}"

    print(f"Cloned outputs match (n={N_COMPARE})")
