# arceus-youki

Youki as the advisory register of an Arceus runner's advisory triage: the runner reads the company's open security
advisories from Youki and, with `post: true`, sends each verdict (`affected`, `fixed`, `not_affected`,
`needs_review`) back to the project in Youki. For teams that keep their advisories in Youki and run Arceus. It is
the Python module `arceus_youki`, which Arceus loads by its name in `secops.register.type`.

## Install

Into the runner's own Python environment (Arceus's setup makes it in `/opt/arceus-runner/venv`), from a clone of this
repository. It declares no dependencies: it uses the runner's `arceus_runner`, `httpx` and `pydantic`.

```sh
git clone <this repository> arceus-youki
/opt/arceus-runner/venv/bin/pip install ./arceus-youki
```

## Configure

In `config.yaml`:

```yaml
secops:
  enabled: true
  register:
    type: arceus_youki
    url: https://youki.example.com      # Youki's address, http or https, without a path
    token_env: ADVISORY_REGISTER_TOKEN  # the default: the variable in secrets.env that holds the token
  post: true                            # false: the verdicts stay in the run's report
```

In `secrets.env`:

```sh
ADVISORY_REGISTER_TOKEN=<a Youki service token>
```

Then run `arceus-runner check`: it asks Youki who the token is.

## The token

A Youki service token with the scope `advisories:read`, and with `post: true` also `verdicts:write` and
`projects:read` (the runner reads a project's verdicts only to settle one whose answer was lost, so it never sends a
verdict twice). A token bound to a GitLab group must cover the project's group, `code_host.group`: that group or
one above it. `clients` covers `clients/acme`; `clients/acm` does not. Youki answers a project outside the token's
group as one it does not know. `arceus-runner check` fails on a missing scope or a group that does not cover the
project, and says which. A 403 is reported with both of its possible causes, which the runner cannot tell apart: the
token lacks rights for the request, or something in front of Youki refused it (an address allowlist, a proxy).

## What it reads and sends

Every request carries the token as `Authorization: Bearer`, and every answer must be Youki's envelope
`{"success", "data", "error"}`; anything else is the register failing, never a guess.

| Request | When |
|---|---|
| `GET /api/v1/token` | `arceus-runner check`: the token's `scopes` and `gitlab_group` |
| `GET /api/v1/advisories?status=open&limit=200`, then `&before=<next_before>` | each run: every page of open advisories, at most 50 |
| `GET /api/v1/advisories/<id>` | each run: each advisory's whole text, its `body` |
| `POST /api/v1/projects/<key>/advisory-verdicts` | with `post: true`, one verdict: `{"advisory": "<id>", "verdict", "evidence"}` |
| `GET /api/v1/projects/<key>/advisory-verdicts` | only to settle a verdict whose answer was lost |

`<key>` is the repository's path on the code host, `<group>/<path>`, URL-encoded whole (`clients%2Facme%2Fsub%2Facme-api`).
Each advisory reaches the agent with Youki's id, its `source_ref`, title and text, and its `facts` as Youki gives them;
the report shows its identifiers, severity, whether it is exploited (`exploited` or `kev` in the facts) and links to
`<url>/advisories/<id>`. An advisory Youki no longer has when its text is asked is left out of the run, and the
report says so. Evidence is at most 4,000 characters, Youki's limit. A verdict Youki refuses is shown in the run's
report in Youki's own words.

## Tests

With the Python environment of an Arceus checkout, which has `arceus_runner`, `httpx`, `pydantic` and `pytest`:

```sh
/path/to/arceus/runner/.venv/bin/python -m pytest -q
```

They run against a stand-in for Youki's API (`httpx.MockTransport`), with no network.

## License

Apache 2.0, see [LICENSE](LICENSE).
