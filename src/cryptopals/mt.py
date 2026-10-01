"""
Mersenne Twister implementation

"""

# Parameters for MT19937
N = 624  # state size (degree of recurrence)
M = 397  # middle word
R = 31  # separation point (of one word)
# coefficients of rational normal form twist matrix
A = 0x9908B0DF
# u, s, t, l are tempering bit shifts
# d, b, c are masks for u, s, t (respectively)
U = 11
D = 0xFFFFFFFF
S = 7
B = 0x9D2C5680
T = 15
C = 0xEFC60000
L = 18

# https://en.wikipedia.org/wiki/Mersenne_Twister#Initialization
INIT_F = 1812433253


def _lowest_32(val: int) -> int:
    """Return lowest 32 bits of argument"""
    return val & 0xFFFFFFFF


class MersenneTwister:
    def __init__(self, seed: int = 0):
        self.state = [0 for _ in range(N)]
        self.initialize_generator(seed)

    def initialize_generator(self, seed: int):
        if seed < 0:
            raise ValueError(f"Expected non-negative seed (got {seed})")
        if seed >= 2**32:
            raise ValueError(f"Seed must be 32 bits (got {seed})")
        self.state[0] = seed
        for i in range(1, N):
            last = self.state[i - 1]
            recurrence = INIT_F * (last ^ (last >> 30)) + i
            # ensure we take the lowest 32 bits
            self.state[i] = _lowest_32(recurrence)
        self.index = N

    def twist(self):
        lower_mask = (1 << R) - 1
        # must explicitly mask against 32 bits to get fixed-width negation
        # (python ints use two's complement)
        upper_mask = _lowest_32(~lower_mask)
        for i in range(N):
            # Concatenate the upper bit of i and the lower bits of (i+1) mod n
            next_index = (i + 1) % N
            upper_bit = self.state[i] & upper_mask
            lower_bits = self.state[next_index] & lower_mask
            x = upper_bit | lower_bits
            xA = x >> 1
            if (x & 1) != 0:  # lowest bit is 1
                xA ^= A
            # twist around m
            mid_index = (i + M) % N
            self.state[i] = self.state[mid_index] ^ xA

    # Extract number
    def rand(self) -> int:
        if self.index >= N:
            if self.index > N:
                raise ValueError("Generator was never initialized")
            self.twist()
            self.index = 0

        y = self.state[self.index]
        self.index += 1

        # temper (to improve distribution)
        y ^= (y >> U) & D
        y ^= (y << S) & B
        y ^= (y << T) & C
        y ^= y >> L

        # temper-related masking above will constrain this to 32 bit fixed-width
        return y

    # It's natural to support iteration

    def __iter__(self):
        return self

    def __next__(self):
        return self.rand()
