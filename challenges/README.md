# challenges

One script per challenge, grouped by set:

```
challenges/set01/c01_hex_to_base64.py
challenges/set01/c02_fixed_xor.py
...
challenges/data/                      # shared input files from cryptopals
```

Conventions:

- Name files `cNN_short_slug.py` so they sort in challenge order.
- Import shared primitives from the library: `from cryptopals import xor, scoring`.
- End each script with an inline check against the known answer, e.g.:

  ```python
  if __name__ == "__main__":
      result = solve()
      assert result == EXPECTED, result
      print(result)
  ```

- Scripts are run directly (`uv run python challenges/set01/c01_...py`), not via
  pytest. Only `src/cryptopals/` is covered by the test suite.
