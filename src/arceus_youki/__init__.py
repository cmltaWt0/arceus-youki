"""Youki as the advisory register of an Arceus runner (arceus_runner.integrations.AdvisoryRegister).

    secops:
      register:
        type: arceus_youki
        url: https://youki.example.com
        token_env: ADVISORY_REGISTER_TOKEN   # the default: a Youki service token, in secrets.env

Every request goes through the runner's http.ServiceClient with the token as `Authorization: Bearer`, and every
answer is Youki's envelope `{"success", "data", "error"}`: anything else is the register failing, never a guess. A
refusal is raised with Youki's own words, its `error`, as the contract's `body`, so a run's report shows them; one
without the envelope is not Youki's but something's in front of it (an address allowlist, a proxy), and says so. A
403 names both of its causes: the client gives no body to tell them apart by.
"""

from __future__ import annotations

import json
from urllib.parse import quote, urlsplit

from arceus_runner.checks import Check
from arceus_runner.config import AdvisoryRegisterConfig, HttpConfig
from arceus_runner.http import AuthError, BadRequest, NotFound, ServiceClient, ServiceError
from arceus_runner.integrations import Advisory, Id, RegisterType, RepoAt
from pydantic import field_validator

NAME = "youki"
PAGE = 200            # Youki's largest page
MAX_PAGES = 50        # 10,000 open advisories: past that it is a cursor that does not move, not a list to read
MAX_EVIDENCE = 4000   # Youki's limit
READ = ("advisories:read",)
WRITE = ("verdicts:write", "projects:read")  # projects:read: how a verdict whose answer was lost is looked up


class YoukiConfig(AdvisoryRegisterConfig):
    url: str                                    # Youki's address, without a path: https://youki.example.com
    token_env: str = "ADVISORY_REGISTER_TOKEN"  # its service token, in secrets.env

    @field_validator("url")
    @classmethod
    def _address(cls, v: str) -> str:
        u = urlsplit(v)
        if u.scheme not in ("http", "https") or not u.hostname or u.path not in ("", "/"):
            raise ValueError(f"must be Youki's address without a path, like https://youki.example.com, not {v!r}")
        return v.rstrip("/")


def _envelope(text: str) -> dict:
    """Youki's envelope in an answer's text, or {} when it is not one."""
    try:
        body = json.loads(text)
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _str(value: object) -> str:
    return value if isinstance(value, str) else ""


def _strs(value: object) -> list[str]:
    return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []


def _verdicts(repo: RepoAt) -> str:
    """The project's verdicts: Youki names a project by its path on the code host, here URL-encoded whole."""
    return f"/api/v1/projects/{quote(f'{repo.group}/{repo.path}', safe='')}/advisory-verdicts"


class YoukiRegister:
    receives = True
    max_evidence = MAX_EVIDENCE

    def __init__(self, cfg: YoukiConfig, client: ServiceClient):
        self.cfg = cfg
        self.client = client

    def _data(self, method: str, path: str, want: type, **kwargs):
        """The `data` of Youki's answer, of the type expected. A refusal is raised again with Youki's words as its
        `body`, a 401 as it is, a 403 naming both of its causes; any other answer without Youki's envelope, a
        refusal's included, is the register failing."""
        what = f"{method} {path}"
        try:
            body = _envelope(self.client.request(method, path, **kwargs).text)
        except AuthError as err:
            if err.status != 403:
                raise  # 401: Youki's refusal of the token
            raise AuthError(NAME, f"{what}: HTTP 403: the token lacks rights for this request, or something in front "
                                  "of Youki refused it (an address allowlist, a proxy)", 403) from None
        except (BadRequest, NotFound) as err:
            words = _envelope(err.body).get("error")
            if not isinstance(words, str):
                raise ServiceError(NAME, f"{what}: HTTP {err.status}, not Youki's answer: something in front of Youki "
                                         "refused the request (an address allowlist, a proxy)") from None
            raise type(err)(NAME, f"{what}: HTTP {err.status}: {words}", err.status, words) from None
        if body.get("success") is not True or not isinstance(body.get("data"), want):
            raise ServiceError(NAME, f"{what}: not Youki's answer")
        return body["data"]

    def open(self) -> list[Advisory]:
        """Every open advisory, page by page, each with its whole text, read on its own."""
        found, params = [], {"status": "open", "limit": PAGE}
        for _ in range(MAX_PAGES):
            page = self._data("GET", "/api/v1/advisories", dict, params=params)
            items = page.get("items")
            if not isinstance(items, list) or not all(isinstance(a, dict) and type(a.get("id")) is int for a in items):
                raise ServiceError(NAME, "GET /api/v1/advisories: a page whose items are not Youki's advisories")
            found += items
            if page.get("next_before") is None:
                return [self._advisory(a) for a in found]
            params = {**params, "before": page["next_before"]}
        raise ServiceError(NAME, f"GET /api/v1/advisories: more than {MAX_PAGES} pages of open advisories")

    def _advisory(self, a: dict) -> Advisory:
        n = a["id"]
        try:
            text, problem = self._text(n), ""
        except NotFound as err:
            text, problem = None, f"Youki no longer had it when its text was asked ({err.body})"
        facts = a.get("facts") if isinstance(a.get("facts"), dict) else {}
        return Advisory(id=n, ref=_str(a.get("source_ref")), title=_str(a.get("title")), text=text,
                        facts=facts, identifiers=_strs(facts.get("identifiers")),
                        severity=_str(facts.get("severity")).lower(),
                        exploited=facts.get("exploited") is True or facts.get("kev") is True,
                        changed=_str(a.get("changed_at")), url=f"{self.cfg.url}/advisories/{n}", problem=problem)

    def _text(self, n: int) -> str:
        path = f"/api/v1/advisories/{n}"
        full = self._data("GET", path, dict).get("advisories")
        body = next((x.get("body") for x in full if isinstance(x, dict) and x.get("id") == n),
                    None) if isinstance(full, list) else None
        if not isinstance(body, str):
            raise ServiceError(NAME, f"GET {path}: no text for advisory {n}")
        return body

    def send(self, advisory: Advisory, repo: RepoAt, verdict: str, evidence: str) -> None:
        self._data("POST", _verdicts(repo), dict,
                   json={"advisory": str(advisory.id), "verdict": verdict, "evidence": evidence})

    def latest(self, advisory: Id, repo: RepoAt) -> tuple[str, str] | None:
        try:
            held = self._data("GET", _verdicts(repo), list)
        except NotFound:
            return None  # a project Youki does not know, or one outside the token's group
        return next(((x.get("verdict"), x.get("evidence")) for x in held if isinstance(x, dict)
                     and isinstance(x.get("advisory"), dict) and x["advisory"].get("id") == advisory), None)

    def check(self, scope: str, post: bool) -> list[Check]:
        """Youki answers to the token, which has the scopes a run uses and, bound to a group, covers `scope`."""
        try:
            token = self._data("GET", "/api/v1/token", dict)
        except ServiceError as err:
            return [Check("youki.token", "fail", str(err))]
        scopes, group = _strs(token.get("scopes")), token.get("gitlab_group") or ""
        missing = [s for s in READ + (WRITE if post else ()) if s not in scopes]
        if missing:
            return [Check("youki.token", "fail", f"{self.cfg.url} answers, but the token lacks {', '.join(missing)}")]
        if group and scope != group and not scope.startswith(f"{group}/"):
            return [Check("youki.token", "fail", f"the token is bound to the group {group}, which does not hold "
                                                 f"{scope}: Youki would not know its projects")]
        return [Check("youki.token", "ok", f"{self.cfg.url} answers; the token has {', '.join(scopes)}, "
                                           + (f"bound to {group}" if group else "for every group"))]

    def close(self) -> None:
        self.client.close()


def _build(cfg: YoukiConfig, token: str | None, http: HttpConfig, transport=None) -> YoukiRegister:
    headers = {"Authorization": f"Bearer {token}"}
    return YoukiRegister(cfg, ServiceClient(NAME, cfg.url, headers, http, transport=transport))


REGISTER = RegisterType(config=YoukiConfig, build=_build)
