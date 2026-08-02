"""Parser-level tests only — `_up`/`_down` construct a `RealIncusClient`
and shell out to a real `incus`, which this VM doesn't have (see
NEEDS-HUMAN.md). The orchestration those wrap is already exercised
end-to-end against fakes in test_app.py / test_acceptance.py; this file
just proves the argument plumbing is correct.
"""

import pytest

from warden.cli import build_parser


def test_up_requires_flavor_and_llm():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["up"])


def test_up_rejects_unknown_flavor():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["up", "--flavor", "nope", "--llm", "claude"])


def test_up_defaults():
    parser = build_parser()
    args = parser.parse_args(["up", "--flavor", "monitored", "--llm", "gemini"])
    assert args.project == "warden"
    assert args.mem == "4GiB"
    assert args.cpu == "2"
    assert args.name is None
    assert args.extra_allow == []
    assert args.repo_url is None


def test_up_repeated_allow_flags_accumulate():
    parser = build_parser()
    args = parser.parse_args([
        "up", "--flavor", "builder", "--llm", "claude",
        "--allow", "a.example.com", "--allow", "b.example.com",
    ])
    assert args.extra_allow == ["a.example.com", "b.example.com"]


def test_down_requires_instance_positional():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["down"])
    args = parser.parse_args(["down", "cap-1"])
    assert args.instance == "cap-1"
    assert args.project == "warden"
