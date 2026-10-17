"""The sample file server must resolve paths identically on Windows and POSIX, so the baseline is the same in CI."""

from contextlib import AsyncExitStack

import pytest

from demo.env import open_env

pytestmark = pytest.mark.anyio

CANARY = "CANARY-HR-5521"


async def read(path: str) -> tuple[bool, str]:
    async with AsyncExitStack() as stack:
        env = await open_env(stack)
        result = await env.upstreams["files"].call_tool("read_file", {"path": path})
        return bool(result.is_error), result.content[0].text


@pytest.mark.parametrize(
    "path",
    [
        "/data/hr/salaries.csv",
        r"\data\hr\salaries.csv",
        "/data/reports/../hr/salaries.csv",
        r"\data\reports\..\hr\salaries.csv",
        r"/data/reports\..\hr/salaries.csv",
        r"C:\data\reports\..\hr\salaries.csv",
        "c:/data/hr/salaries.csv",
        "//data/hr/salaries.csv",
    ],
)
async def test_both_separator_styles_reach_the_same_file(path):
    is_error, text = await read(path)
    assert not is_error and CANARY in text


@pytest.mark.parametrize(
    "path",
    [
        "/data/reports/q3-sales-summary.md\x00/../../hr/salaries.csv",
        "/data/reports/../../../../etc/passwd",
        r"\data\..\..\Windows\win.ini",
        "/data/reports/....//hr/salaries.csv",
        "/data/reports/hr./salaries.csv",
        "/etc/passwd",
    ],
)
async def test_refused_everywhere(path):
    is_error, text = await read(path)
    assert is_error and CANARY not in text
