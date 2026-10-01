"""
Mersenne Twister implementation

"""

# https://en.wikipedia.org/wiki/Mersenne_Twister#Initialization
INIT_F = 1812433253


def _lowest_32(val: int) -> int:
    """Return lowest 32 bits of argument"""
    return val & 0xFFFFFFFF


class MersenneTwister:
    def __init__(
        self,
        recurrence: int = 624,
        middle_word: int = 397,
        separation_point: int = 31,
        # coefficients of rational normal form twist matrix
        a: int = 0x9908B0DF,
        # u, s, t, l are tempering bit shifts
        # d, b, c are masks for u, s, t (respectively)
        u: int = 11,
        d: int = 0xFFFFFFFF,
        s: int = 7,
        b: int = 0x9D2C5680,
        t: int = 15,
        c: int = 0xEFC60000,
        l: int = 18,
    ):
        self.n = recurrence
        self.m = middle_word
        self.r = separation_point
        self.a = a
        self.u, self.d = u, d
        self.s, self.b = s, b
        self.t, self.c = t, c
        self.l = l

        self.MT = [0 for _ in range(self.n)]
        self.index = self.n + 1

    def initialize_generator(self, seed: int):
        if seed < 0:
            raise ValueError(f"Expected non-negative seed (got {seed})")
        if seed >= 2**32:
            raise ValueError(f"Seed must be 32 bits (got {seed})")
        self.MT[0] = seed
        for i in range(1, self.n):
            last = self.MT[i - 1]
            recurrence = INIT_F * (last ^ (last >> 30)) + i
            # ensure we take the lowest 32 bits
            self.MT[i] = _lowest_32(recurrence)
        self.index = self.n

    def twist(self):
        lower_mask = (1 << self.r) - 1
        # must explicitly mask against 32 bits to get fixed-width negation
        # (python ints use two's complement)
        upper_mask = _lowest_32(~lower_mask)
        for i in range(self.n):
            # Concatenate the upper bit of i and the lower bits of (i+1) mod n
            next_index = (i + 1) % self.n
            upper_bit = self.MT[i] & upper_mask
            lower_bits = self.MT[next_index] & lower_mask
            x = upper_bit | lower_bits
            xA = x >> 1
            if (x & 1) != 0:  # lowest bit is 1
                xA ^= self.a
            # twist around m
            mid_index = (i + self.m) % self.n
            self.MT[i] = self.MT[mid_index] ^ xA

    def extract_number(self) -> int:
        if self.index >= self.n:
            if self.index > self.n:
                raise ValueError("Generator was never initialized")
            self.twist()
            self.index = 0

        y = self.MT[self.index]
        self.index += 1

        # temper (to improve distribution)
        y ^= (y >> self.u) & self.d
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= y >> self.l

        # temper-related masking above will constrain this to 32 bit fixed-width
        return y


# construct an instance to support module functions

_TWISTER = MersenneTwister()
_TWISTER.initialize_generator(0)


def seed(seed: int):
    _TWISTER.initialize_generator(seed)


def rand() -> int:
    return _TWISTER.extract_number()
