# Contributing

## Engineering rules

- Do not add a vendor claim without a ground-truth fixture and validation report.
- Keep evidence parsing independent from web, database and presentation code.
- Return structured warnings; do not print from library code.
- Record source byte extents for every recovered artifact.
- Prefer explicit unsupported/inconclusive results over guesses.
- Review licences for code, datasets and model weights independently.
- Never place secrets, real evidence or biometric galleries in the repository.

## Before submitting a change

```bash
ruff check .
mypy
pytest --cov
```

A recovery change must include positive, negative, truncated and corrupt-input tests. A security-sensitive change must update the threat model or explain why it does not affect it.

