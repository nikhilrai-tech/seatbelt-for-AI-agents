## What and why

## Checklist

- [ ] Tests pass (`python -m pytest -q`) and `python -m pyflakes src tests` is clean
- [ ] New or changed rule: corpus lines for the dangerous forms **and** at least two everyday commands that stay `ALLOW`
- [ ] No real secrets, hostnames, account ids or names in code, tests or docs (build key-shaped samples at runtime)
- [ ] Nothing executes content from the project being checked (no `git`, `kubectl`, scripts)
- [ ] README / CHANGELOG updated if a user would notice
