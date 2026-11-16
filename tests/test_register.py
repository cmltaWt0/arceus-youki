"""arceus_youki against a stand-in for Youki's API: its section, what it reads, what it sends, what `check` says."""

from __future__ import annotations

import json
import re
from urllib.parse import unquote

import httpx
import pytest
from arceus_runner.config import HttpConfig, SecOpsConfig
from arceus_runner.http import AuthError, BadRequest, NotFound, ServiceError, TransientError
from arceus_runner.integrations import Advisory, RepoAt, register_type
from pydantic import ValidationError

from arceus_youki import MAX_PAGES, REGISTER, YoukiConfig

URL = "https://youki.example.com"
TOKEN = "test-token-not-a-secret"
GROUP = "clients/acme"
ALL = ["advisories:read", "projects:read", "verdicts:write"]
PLATFORM = RepoAt("acme-platform", GROUP, f"https://git.example.com/{GROUP}/acme-platform.git", "a" * 40)
API = RepoAt("sub/acme-api", GROUP, f"https://git.example.com/{GROUP}/sub/acme-api.git", "b" * 40)


def answer(status: int, data=None, error: str | None = None) -> httpx.Response:
    return httpx.Response(status, json={"success": error is None, "data": data, "error": error,
                                        "timestamp": "2099-01-01T00:00:00Z"})


def advisory(n: int, **facts) -> dict:
    """An advisory in full, as `GET /api/v1/advisories/<id>` gives it; the list leaves out its `body`."""
    return {"id": n, "source": "tracker", "source_ref": f"SEC-{n}", "title": f"acme-imagelib: flaw {n}",
            "status": "open", "changed_at": f"2099-01-{n:02d}T10:00:00Z", "body": f"acme-imagelib before 2.4.1 ({n}).",
            "facts": {"identifiers": [f"CVE-2099-{1000 + n}"], "severity": "High", "exploited": False, "kev": False,
                      "affected": "acme-imagelib < 2.4.1", "fixed": ["2.4.1"], **facts}}


class Youki:
    """A stand-in for Youki's API as the adapter uses it: open advisories paged by id, newest first; each project's
    latest verdict per advisory; every request recorded. A request without the token gets 401."""

    def __init__(self):
        self.advisories = {n: advisory(n) for n in (11, 12)}
        self.page = 200                  # the most it lists at once
        self.gone: set[int] = set()      # listed, but gone when its text is asked
        self.broken: set[int] = set()    # listed, but its text is behind an outage (502)
        self.several: set[int] = set()   # keys a verdict cannot be given on: they name more than one advisory (409)
        self.also: dict[int, list[int]] = {}  # older advisories a key also matches: Youki gives them all, oldest first
        self.projects: dict[str, dict] = {f"{GROUP}/acme-platform": {}, f"{GROUP}/sub/acme-api": {}}
        self.token = {"kind": "token", "name": "acme-triage", "scopes": list(ALL), "gitlab_group": "clients"}
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.headers.get("authorization") != f"Bearer {TOKEN}":
            return answer(401, error="Not authenticated")
        path, q = request.url.raw_path.decode().partition("?")[0], request.url.params
        if path == "/api/v1/token":
            return answer(200, self.token)
        if path == "/api/v1/advisories":
            ids = sorted((n for n in self.advisories if "before" not in q or n < int(q["before"])), reverse=True)
            page = ids[:min(int(q["limit"]), self.page)]
            return answer(200, {"items": [{k: v for k, v in self.advisories[n].items() if k != "body"} for n in page],
                                "total": len(ids), "next_before": page[-1] if len(ids) > len(page) else None})
        if m := re.fullmatch(r"/api/v1/advisories/(\d+)", path):
            if int(m[1]) in self.gone:
                return answer(404, error=f"No advisory has the key '{m[1]}'")
            if int(m[1]) in self.broken:
                return httpx.Response(502, text="Bad Gateway")
            matched = [self.advisories[n] for n in sorted({int(m[1]), *self.also.get(int(m[1]), ())})]
            return answer(200, {"key": m[1], "advisories": matched, "total": len(matched)})
        m = re.fullmatch(r"/api/v1/projects/([^/]+)/advisory-verdicts", path)
        held = self.projects.get(unquote(m[1])) if m else None
        if held is None:
            return answer(404, error="No such project")
        if request.method == "GET":
            return answer(200, list(held.values()))
        body = json.loads(request.content)
        if body["verdict"] not in ("affected", "fixed", "not_affected", "needs_review"):
            return answer(400, error=f"verdict: {body['verdict']!r} is not one of the four words")
        n = int(body["advisory"])
        if n in self.several:
            return answer(409, error=f"'{n}' names more than one advisory: give Youki's id")
        held[n] ={"advisory": {"id": n, "source_ref": f"SEC-{n}"}, "project": {"path": unquote(m[1])},
                   "verdict": body["verdict"], "evidence": body["evidence"], "stale": False}
        return answer(201, held[n])


def down(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused")


def fenced(request: httpx.Request) -> httpx.Response:
    """What stands in front of Youki, refusing an address it does not allow, and quoting the request as it does."""
    return httpx.Response(403, text=f"<html>403 Forbidden: {request.headers['authorization']}</html>")


def build(handler, token: str = TOKEN):
    return REGISTER.build(YoukiConfig(type="arceus_youki", url=URL), token, HttpConfig(), httpx.MockTransport(handler))


@pytest.fixture
def youki() -> Youki:
    return Youki()


# -- the section ----------------------------------------------------------------------------------------------------

def test_type_arceus_youki_is_this_register_with_its_token_by_default():
    section = SecOpsConfig.model_validate({"enabled": True, "register": {"type": "arceus_youki", "url": URL + "/"}})
    assert register_type("arceus_youki") is REGISTER
    assert section.register_section == YoukiConfig(type="arceus_youki", url=URL, token_env="ADVISORY_REGISTER_TOKEN")


@pytest.mark.parametrize("section", [
    pytest.param({"url": URL, "project": "acme"}, id="unknown-key"),
    pytest.param({"url": URL + "/api"}, id="a-path"),
    pytest.param({"url": "ftp://youki.example.com"}, id="not-http"),
    pytest.param({"url": "https://"}, id="no-host"),
])
def test_a_section_that_is_not_youkis_is_refused(section):
    with pytest.raises(ValidationError):
        SecOpsConfig.model_validate({"enabled": True, "register": {"type": "arceus_youki", **section}})


def test_it_takes_verdicts_of_up_to_4000_characters(youki):
    reg = build(youki)
    assert (reg.receives, reg.max_evidence) == (True, 4000)


# -- what it reads ---------------------------------------------------------------------------------------------------

def test_open_reads_every_page_and_each_advisory_whole(youki):
    youki.advisories = {n: advisory(n) for n in (11, 12, 13, 14, 15)}
    youki.advisories[11]["facts"] = None  # one Youki could not parse
    youki.advisories[13]["facts"]["identifiers"].append(None)
    youki.advisories[13]["facts"]["kev"] = True
    youki.advisories[14]["facts"]["exploited"] = True
    youki.also[13] = [12]
    youki.page = 2
    found = build(youki).open()
    lists = [dict(r.url.params) for r in youki.requests if r.url.path == "/api/v1/advisories"]
    assert lists == [{"status": "open", "limit": "200"}, {"status": "open", "limit": "200", "before": "14"},
                     {"status": "open", "limit": "200", "before": "12"}]
    assert [a.id for a in found] == [15, 14, 13, 12, 11] and [a.exploited for a in found] == [0, 1, 1, 0, 0]
    assert (found[4].facts, found[4].identifiers, found[4].severity) == ({}, [], "")
    assert found[2] == Advisory(
        id=13, ref="SEC-13", title="acme-imagelib: flaw 13", text="acme-imagelib before 2.4.1 (13).",
        facts=youki.advisories[13]["facts"], identifiers=["CVE-2099-1013"], severity="high", exploited=True,
        changed="2099-01-13T10:00:00Z", url=f"{URL}/advisories/13")


def test_an_advisory_gone_when_its_text_is_asked_comes_without_it(youki):
    youki.gone.add(12)
    gone, kept = build(youki).open()
    assert (gone.id, gone.text, gone.problem) == (
        12, None, "Youki no longer had it when its text was asked (No advisory has the key '12')")
    assert (kept.text, kept.problem) == ("acme-imagelib before 2.4.1 (11).", "")


def test_an_outage_on_one_text_fails_the_whole_read(youki):
    youki.broken.add(12)
    with pytest.raises(TransientError):  # tried again by the runner, never an advisory dropped
        build(youki).open()


def test_a_list_that_never_ends_is_the_register_failing():
    asked = []

    def endless(request):
        asked.append(request)
        return answer(200, {"items": [], "next_before": 1})

    with pytest.raises(ServiceError, match=f"more than {MAX_PAGES} pages"):
        build(endless).open()
    assert len(asked) == MAX_PAGES


@pytest.mark.parametrize("status, content", [
    pytest.param(200, {"items": [], "next_before": None}, id="no-envelope"),
    pytest.param(200, {"success": True, "data": [], "error": None}, id="data-not-an-object"),
    pytest.param(200, {"success": False, "data": {"items": [], "next_before": None}, "error": None}, id="no-success"),
    pytest.param(200, {"success": True, "data": {"items": [11], "next_before": None}, "error": None},
                 id="an-item-that-is-not-an-object"),
    pytest.param(200, {"success": True, "data": {"items": [{"source_ref": "SEC-11"}], "next_before": None},
                       "error": None}, id="an-item-without-youkis-number"),
    pytest.param(200, [], id="json-not-an-object"),
    pytest.param(200, "<html>a proxy's page</html>", id="not-json"),
    pytest.param(404, "<html>Not Found</html>", id="a-refusal-without-youkis-words"),
])
def test_an_answer_that_is_not_youkis_is_the_register_failing(status, content):
    raw = content if isinstance(content, str) else json.dumps(content)
    with pytest.raises(ServiceError) as err:
        build(lambda request: httpx.Response(status, text=raw)).open()
    assert type(err.value) is ServiceError  # not a refusal, which the runner would keep as the register's words


def test_an_advisory_whose_text_youki_does_not_give_is_the_register_failing(youki):
    del youki.advisories[12]["body"]
    with pytest.raises(ServiceError, match="no text for advisory 12"):
        build(youki).open()


# -- what it sends ---------------------------------------------------------------------------------------------------

def test_send_posts_the_verdict_to_the_project_by_its_whole_path(youki):
    build(youki).send(Advisory(id=11, ref="SEC-11", title="", text=None, facts={}), API, "affected", "pinned at 2.3.0")
    [post] = [r for r in youki.requests if r.method == "POST"]
    assert post.url.raw_path == b"/api/v1/projects/clients%2Facme%2Fsub%2Facme-api/advisory-verdicts"
    assert post.headers["content-type"] == "application/json"
    assert json.loads(post.content) == {"advisory": "11", "verdict": "affected", "evidence": "pinned at 2.3.0"}


@pytest.mark.parametrize("repo, n, verdict, refusal, status, words", [
    pytest.param(PLATFORM, 11, "maybe", BadRequest, 400, "verdict: 'maybe' is not one of the four words", id="400"),
    pytest.param(RepoAt("acme-gone", GROUP, "", ""), 11, "affected", NotFound, 404, "No such project", id="404"),
    pytest.param(PLATFORM, 13, "affected", BadRequest, 409, "'13' names more than one advisory: give Youki's id",
                 id="409"),
])
def test_a_refusal_carries_youkis_own_words(youki, repo, n, verdict, refusal, status, words):
    youki.several.add(13)
    with pytest.raises(refusal) as err:
        build(youki).send(Advisory(id=n, ref=f"SEC-{n}", title="", text=None, facts={}), repo, verdict, "evidence")
    assert (err.value.status, err.value.body) == (status, words)


def test_latest_is_the_projects_latest_verdict_on_that_advisory(youki):
    reg = build(youki)
    for n, word in ((12, "fixed"), (11, "needs_review"), (11, "affected")):
        reg.send(Advisory(id=n, ref=f"SEC-{n}", title="", text=None, facts={}), PLATFORM, word, f"{word} on {n}")
    assert reg.latest(11, PLATFORM) == ("affected", "affected on 11")
    assert reg.latest(11, API) is None
    assert reg.latest(11, RepoAt("acme-gone", GROUP, "", "")) is None  # a project Youki does not know
    with pytest.raises(TransientError):  # no answer is not "none held": the runner must not send it again
        build(down).latest(11, PLATFORM)


# -- arceus-runner check ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("group, scopes, post, said", [
    pytest.param("clients", ALL, True, f"{URL} answers; the token has {', '.join(ALL)}, bound to clients", id="parent"),
    pytest.param(GROUP, ALL, True, f"the token has {', '.join(ALL)}, bound to {GROUP}", id="the-group"),
    pytest.param(None, ALL, True, f"the token has {', '.join(ALL)}, for every group", id="unbound"),
    pytest.param("clients", ["advisories:read"], False, "the token has advisories:read, bound", id="read-only"),
])
def test_check_names_the_scopes_and_the_group(youki, group, scopes, post, said):
    youki.token.update(gitlab_group=group, scopes=scopes)
    [c] = build(youki).check(GROUP, post)
    assert c.status == "ok" and said in c.detail


@pytest.mark.parametrize("change, post, said", [
    pytest.param({"scopes": ["projects:read", "verdicts:write"]}, False, "lacks advisories:read", id="read"),
    pytest.param({"scopes": ["advisories:read", "projects:read"]}, True, "lacks verdicts:write", id="write"),
    pytest.param({"scopes": ["advisories:read", "verdicts:write"]}, True, "lacks projects:read", id="look-up"),
    pytest.param({"gitlab_group": "clients/acm"}, True, "bound to the group clients/acm, which does not hold "
                 f"{GROUP}", id="a-sibling-group"),
    pytest.param({"gitlab_group": f"{GROUP}/sub"}, True, f"bound to the group {GROUP}/sub, which does not hold "
                 f"{GROUP}", id="a-child-group"),
])
def test_check_fails_on_a_token_that_does_not_do(youki, change, post, said):
    youki.token.update(change)
    [c] = build(youki).check(GROUP, post)
    assert c.status == "fail" and said in c.detail


def test_check_fails_when_youki_refuses_the_token_or_does_not_answer(youki):
    [refused] = build(youki, token="another-token").check(GROUP, False)
    [silent] = build(down).check(GROUP, False)
    assert refused.status == "fail" and "GET /api/v1/token: HTTP 401 (token invalid or lacks rights)" in refused.detail
    assert silent.status == "fail" and "GET /api/v1/token: ConnectError" in silent.detail


def test_a_403_names_the_token_and_what_stands_in_front_of_youki_alike():
    [c] = build(fenced).check(GROUP, False)
    with pytest.raises(AuthError) as err:  # a run's reason: not worth trying again
        build(fenced).open()
    assert (c.status, c.detail) == ("fail", "youki: GET /api/v1/token: HTTP 403: the token lacks rights for this "
                                            "request, or something in front of Youki refused it (an address "
                                            "allowlist, a proxy)")
    assert "an address allowlist" in str(err.value) and TOKEN not in str(err.value) + c.detail


def test_the_token_is_in_no_check_and_no_error_the_adapter_raises(youki):
    def quoting(request):  # a register that quotes the request's token in its refusal
        return answer(400, error=f"not for {request.headers['authorization']}")

    said = [c.detail for handler in (youki, quoting, fenced, down) for c in build(handler).check(GROUP, True)]
    calls = (lambda r: r.open(), lambda r: r.latest(11, PLATFORM),
             lambda r: r.send(Advisory(id=11, ref="SEC-11", title="", text=None, facts={}), PLATFORM, "fixed", "x"))
    for handler in (quoting, fenced, down):
        for call in calls:
            with pytest.raises(ServiceError) as err:
                call(build(handler))
            said += [str(err.value), err.value.body]
    assert len(said) == 22 and not [s for s in said if TOKEN in s]


def test_close_closes_the_client(youki):
    reg = build(youki)
    reg.close()
    with pytest.raises(RuntimeError, match="closed"):
        reg.open()
