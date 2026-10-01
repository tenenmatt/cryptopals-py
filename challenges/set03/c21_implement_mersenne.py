from itertools import islice

from cryptopals.mt import MersenneTwister

if __name__ == "__main__":
    # 5489 is the standard seed for MT19937, so we can compare against known values
    twister = MersenneTwister(5489)
    rands = list(islice(twister, 10000))
    assert rands[0] == 3499211612
    assert rands[-1] == 4123659995
