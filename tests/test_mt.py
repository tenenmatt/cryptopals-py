import random
from itertools import islice

import pytest
from hypothesis import given
from hypothesis import strategies as st

import cryptopals.mt as mt


def test_known_outcomes():
    # reference seed(5489) -> 3499211612 at 0 and 4123659995 at 10,000
    twister = mt.MersenneTwister(5489)
    assert twister.rand() == 3499211612
    # skip to 10,000th draw
    for _ in range(9998):
        twister.rand()
    # now check 10K
    assert twister.rand() == 4123659995


@pytest.mark.parametrize("seed", [0, 0xC0FFE3, 2**32 - 1])
def test_against_reference(seed):
    twister = mt.MersenneTwister(seed)
    r = random.Random()
    # version 3 state with my twister internals
    state = (3, tuple(twister.state) + (624,), None)
    r.setstate(state)
    iterations = 2000
    ours = [twister.rand() for _ in range(iterations)]
    theirs = [r.getrandbits(32) for _ in range(iterations)]
    assert ours == theirs


def test_bounds_clamp():
    with pytest.raises(ValueError, match="non-negative"):
        mt.MersenneTwister(-1)
    with pytest.raises(ValueError, match="must be 32 bits"):
        mt.MersenneTwister(2**32)


def test_iteration():
    twister = mt.MersenneTwister(5489)
    assert next(twister) == 3499211612


@given(st.integers(0, 2**32 - 1))
def test_repeated_iteration(seed):
    left = mt.MersenneTwister(seed)
    right = mt.MersenneTwister(seed)
    assert list(islice(left, 100)) == list(islice(right, 100))
