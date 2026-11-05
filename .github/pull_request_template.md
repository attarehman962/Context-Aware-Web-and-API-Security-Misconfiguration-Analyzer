<!--
Branch name must be <name>/pNN-topic, e.g. atta/p01-repo-setup, or, for a
review fix in a partner's files, <name>/fix-<partner>-pNN-topic, e.g.
atta/fix-asim-p11-check-specs (name and partner: atta | asim | neelam).
CI rejects other branch names.
-->

## What & why

<!-- What does this PR change, and why? Link the issue or phase task. -->

## Area

- [ ] Backend / engine (Atta)
- [ ] Frontend (Neelam)
- [ ] Specs, CVSS mapping, ML, eval (Asim)

## How I tested it

<!-- Commands run and results, e.g. `make test`, `make lint`, manual checks. -->

## Checklist

- [ ] I only edited files I own, or the owner agreed (say who)
- [ ] `make lint` and `make test` pass locally
- [ ] Tests added/updated for new behaviour
- [ ] Schema changes include an Alembic migration (upgrade and downgrade tested)
- [ ] Docs / CLAUDE.md updated if behaviour, commands or ownership changed
- [ ] No secrets, real `.env` values or scan data from third-party targets committed
