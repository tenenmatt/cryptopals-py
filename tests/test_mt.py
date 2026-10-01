import random

import pytest

import cryptopals.mt as mt


def test_known_outcomes():
    # reference seed(5489) -> 3499211612 at 0 and 4123659995 at 10,000
    mt.seed(5489)
    assert mt.rand() == 3499211612
    # skip to 10,000th draw
    for _ in range(9998):
        mt.rand()
    # now check 10K
    assert mt.rand() == 4123659995


def test_against_reference():
    for seed in [0, 0xC0FFE3, 2**32 - 1]:
        twister = mt.MersenneTwister()
        twister.initialize_generator(seed)
        r = random.Random()
        # version 3 state with my twister internals
        state = (3, tuple(twister.MT) + (624,), None)
        r.setstate(state)
        iterations = 2000
        ours = [twister.extract_number() for _ in range(iterations)]
        theirs = [r.getrandbits(32) for _ in range(iterations)]
        for observed, expected in zip(ours, theirs, strict=True):
            assert observed == expected


def test_bounds_clamp():
    with pytest.raises(ValueError, match="non-negative"):
        mt.seed(-1)
    with pytest.raises(ValueError, match="must be 32 bits"):
        mt.seed(2**32)
