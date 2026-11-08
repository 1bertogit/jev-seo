# Contributing

Issues and pull requests are welcome.

- Install test dependencies with `pip install -e '.[web,test]'`, then run `python3 -m unittest discover -s tests -v` before sending a change. These offline tests make no network calls and spend nothing.
- Keep the operating rule: a source finds, code decides, Jev judges, Claude writes. Anything a count, status code or string match can decide belongs in code, not in a Jev question.
- A new rule needs a severity, a fix, an official source URL and a test. Mark editorial conventions as heuristics.
- A new or reworded Jev question should come with evidence: decisiveness and agreement on labelled examples, recorded in `references/evaluation.md`.
- No em dashes in code, docs or report text.
