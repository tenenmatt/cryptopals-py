import random
from itertools import islice

import hypothesis.strategies as st
import pytest
from hypothesis import example, given

import cryptopals.mt as mt


def test_known_outcomes():
    # reference seed(5489) -> 3499211612 at 0 and 4123659995 at 10,000
    twister = mt.MersenneTwister(5489)
    assert next(twister) == 3499211612
    # skip to 10,000th draw
    for _ in range(9998):
        next(twister)
    # now check 10K
    assert next(twister) == 4123659995


@pytest.mark.parametrize("seed", [0, 0xC0FFE3, 2**32 - 1])
def test_against_reference(seed):
    twister = mt.MersenneTwister(seed)
    r = random.Random()
    # version 3 state with my twister internals
    state = (3, tuple(twister.state) + (624,), None)
    r.setstate(state)
    iterations = 2000
    ours = list(islice(twister, iterations))
    theirs = [r.getrandbits(32) for _ in range(iterations)]
    assert ours == theirs


def test_seed_out_of_range():
    with pytest.raises(ValueError, match="non-negative"):
        mt.MersenneTwister(-1)
    with pytest.raises(ValueError, match="must be 32 bits"):
        mt.MersenneTwister(2**32)


@given(st.integers(min_value=0, max_value=2**32 - 1))
@example(2**32 - 1)
def test_untemper_identity(y):
    assert mt.untemper(mt.temper(y)) == y


# Both tempering and untempering are combinations of shifts and xor,
# 0 stays stable under all operations.
def test_fixed_point_at_zero():
    assert mt.temper(0) == 0
    assert mt.untemper(0) == 0


def test_untemper_boundaries():
    with pytest.raises(ValueError, match="a 32 bit value"):
        mt.untemper(2**32)
    with pytest.raises(ValueError, match="non-negative value"):
        mt.untemper(-1)


def test_temper_boundaries():
    with pytest.raises(ValueError, match="a 32 bit value"):
        mt.temper(2**32)
    with pytest.raises(ValueError, match="non-negative value"):
        mt.temper(-1)
