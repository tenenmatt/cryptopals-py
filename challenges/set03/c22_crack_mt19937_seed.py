import time
from contextlib import contextmanager
from dataclasses import dataclass
from random import randint

from cryptopals.mt import MersenneTwister


@contextmanager
def pausing(min_pause: int = 5, max_pause: int = 10):
    time.sleep(randint(min_pause, max_pause))
    yield
    time.sleep(randint(min_pause, max_pause))


class Timed:
    """
    Small context manager to capture before/after timestamps for use
    outside the timed context itself.

    """

    def __enter__(self):
        self.earliest = int(time.time())
        return self

    def __exit__(self, *ignored):
        self.latest = int(time.time())


def reseeded(n=10, min_pause=5, max_pause=10) -> tuple[list[int], list[int]]:
    """
    Challenge conditions: some number of generated numbers, with
    unknown waiting times before and after.

    Returns two lists: the generated values, and the (oracle)
    seeds to validate against. Don't peek!
    """
    vals = []
    truth = []
    for _ in range(n):
        with pausing(min_pause, max_pause):
            now = int(time.time())
            mt = MersenneTwister(now)
            truth.append(now)
        vals.append(next(mt))
    return vals, truth


def attack(val: int, earliest: int, latest: int) -> int:
    """
    Brute-force initial value matching `val` from a Twister seeded by
    timestamp between `earliest` and `latest`.

    This assumes our target is always the first value, and that the seed
    is always an integer timestamp between earliest and latest.

    """
    # include latest in checked interval
    for ts in range(earliest, latest + 1):
        if next(MersenneTwister(ts)) == val:
            return ts
    raise ValueError(f"Could not find '{val}' between {earliest} and {latest}")


@dataclass(frozen=True)
class Recovered:
    seed: int
    value: int


def find_seeds(values: list[int], earliest: int, latest: int) -> list[Recovered]:
    return [Recovered(attack(v, earliest, latest), v) for v in values]


def check_results(rec: list[Recovered], truth: list[int]):
    for r, t in zip(rec, truth, strict=True):
        from_truth = next(MersenneTwister(t))
        # true seed matches recovered seed
        assert t == r.seed
        print(
            f"{r.value} (observed) @ {r.seed} (recovered) | proof: {from_truth} from oracle's time"
        )


if __name__ == "__main__":
    # generate values, with pauses before/after each seeding
    with Timed() as t:
        nums, truth = reseeded(1)

    # recover seeds
    recovered = find_seeds(nums, t.earliest, t.latest)
    check_results(recovered, truth)
