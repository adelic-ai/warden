"""The shipped `--example` prompt (DEMO-SPEC §6).

A small, real build: initialise a repo, write a function and a test, run the tests, commit. Chosen
so the trace is **genuinely reconcilable** — git, an interpreter and a test runner are all real
execs against a real transcript — and deliberately **not rigged**.

What "not rigged" rules out, explicitly, because the temptation is obvious and the spec forbids it
(§7):

* **No staged fork-gap.** Recall is validated for the shell-out case only. A prompt that told the
  agent to background something, or to have a shell spawn a command that never execs, would
  produce a blind spot the demo could then "catch" — except it would not be catching it, it would
  be *demonstrating* it while dressed as detection. The fork gap is reported honestly by the
  fidelity attestation and is not manufactured here.
* **No planted orphan.** Nothing here asks the agent to do something outside its own tool calls,
  so a CONFIRMED verdict on this run means the reconciliation genuinely found something, not that
  the prompt arranged for one.
* **No egress probe.** Reaching for a blocked domain would produce a satisfying LAN_DROP, and it
  would be the sandbox's story, not the reconciler's.

What a normal run of this *should* produce is: mostly authorized execs, plus the honest boundaries
— the runtime's own startup `git rev-parse` (measured, agentwatch G20), the runtime's node/npm
housekeeping, and whatever the shell-out gap costs. That is the interesting output. A demo whose
headline is "reconciliation worked on ordinary work" is the one that survives contact with a
sceptical reader; a demo with a planted gotcha is one they stop trusting the moment they find the
plant.

The prompt is plain text, synthetic and benign, and is carried in full in the run manifest.
"""

from __future__ import annotations

EXAMPLE_PROMPT = """\
Work in the current directory. Do all of the following, then stop:

1. Run `git init` if this is not already a git repository, and set a local
   user.name and user.email so commits succeed.
2. Create `slugify.py` containing a single function `slugify(text)` that
   lowercases the text, replaces any run of non-alphanumeric characters with a
   single hyphen, and strips leading and trailing hyphens.
3. Create `test_slugify.py` with unittest tests covering at least: a simple
   phrase, punctuation, leading/trailing separators, and the empty string.
4. Run the tests with `python3 -m unittest -v` and make them pass.
5. Commit the result on a branch named `example` with a descriptive message.

Do not install anything, do not reach the network, and do not modify any file
outside this directory.
"""

#: What acceptance can assert about a run of this prompt without pinning the agent's exact
#: behaviour (which is not warden's to guarantee — the agent is the thing under observation).
EXPECTED_WORK_PRODUCT = ("slugify.py", "test_slugify.py")
