import collections

import pytest

from mcp_firewall.evaluation import CATEGORIES, load_suite, policy_for, run_case

from .conftest import ROOT

SUITE = load_suite(ROOT / "eval" / "suite.jsonl")


def test_suite_shape():
    assert 100 <= len(SUITE) <= 200
    assert len({c["id"] for c in SUITE}) == len(SUITE)
    cats = collections.Counter(c["category"] for c in SUITE)
    assert set(cats) == {*CATEGORIES, "benign"}
    assert cats["benign"] >= 40
    for c in SUITE:
        assert c["label"] in ("attack", "benign")
        assert c["source"]
        assert c["split"] in ("dev", "test")


CASES = {c["id"]: c for c in SUITE}


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("cid", "mode", "expect"),
    [
        ("pt-00", "none", True),
        ("pt-00", "rules", False),
        ("sq-delete", "none", True),
        ("sq-delete", "rules", False),
        ("ii-own-html-comment", "none", True),
        ("ii-own-html-comment", "rules", False),
        ("se-aws", "none", True),
        ("se-aws", "rules", False),
        ("sm-cc-field", "none", True),
        ("sm-cc-field", "rules", False),
    ],
)
async def test_attack_cases(policy, cid, mode, expect):
    row = await run_case(CASES[cid], mode, policy_for(policy, mode), None)
    assert row["success"] is expect


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize("cid", ["bn-read-00", "bn-sql-02", "bn-mail-01", "bn-hard-helpdesk"])
async def test_benign_cases_pass(policy, cid):
    row = await run_case(CASES[cid], "rules", policy_for(policy, "rules"), None)
    assert not row["false_block"] and row["useful"]
