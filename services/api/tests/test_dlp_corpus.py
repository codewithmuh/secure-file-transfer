"""NFR-25 on the synthetic corpus ([DLP] section 8): each detector meets its precision and recall.

About 20,000 documents on every run. Set DLP_CORPUS_SCALE=10 for the nightly run of about 200,000.
Failure messages name detectors, layouts, documents and counts, never a value.
"""

import os
from collections import Counter

import pytest

from dlp_corpus.generate import BANK_CODES, DETECTORS, Document, generate_corpus, keyword_list
from dlp_corpus.score import TARGETS, failures, score, table
from sft.dlp.detect import BUILTIN_DETECTORS
from sft.dlp.detect.scanner import _Scanner


@pytest.fixture(scope="module")
def corpus() -> list[Document]:
    return generate_corpus(scale=float(os.environ.get("DLP_CORPUS_SCALE", "1")))


def test_every_detector_meets_its_nfr_25_target(corpus: list[Document]) -> None:
    leaks: list[str] = []
    scores = score(corpus, [keyword_list()], leaks)
    below = failures(scores)
    assert not below, "\n" + table(scores) + "\n" + "\n".join(below)
    # Each detector was measured on its positives, in every layout it has.
    measured = {detector for detector, _ in scores}
    assert measured == set(TARGETS)
    # No finding shows a labelled value (FR-53, NFR-26).
    assert leaks == []


def test_the_corpus_covers_every_built_in_detector(corpus: list[Document]) -> None:
    assert set(DETECTORS) == BUILTIN_DETECTORS
    assert set(TARGETS) - {"custom:corpus-keywords"} == BUILTIN_DETECTORS
    parts = Counter((doc.detector, doc.part) for doc in corpus)
    for detector in DETECTORS:
        assert parts[(detector, "positives")] > 0
        assert parts[(detector, "hard_negatives")] > 0
    assert parts[("custom:corpus-keywords", "keywords")] > 0
    assert len(corpus) >= 19_000


def test_the_corpus_is_the_same_for_the_same_seed() -> None:
    first = generate_corpus(seed=7, scale=0.05)
    second = generate_corpus(seed=7, scale=0.05)
    assert [d.units for d in first] == [d.units for d in second]
    assert [d.expected for d in first] == [d.expected for d in second]
    assert [d.units for d in generate_corpus(seed=8, scale=0.05)] != [d.units for d in first]


def test_document_names_and_labels_show_no_value(corpus: list[Document]) -> None:
    for doc in corpus[:: max(1, len(corpus) // 2000)]:
        for expected in doc.expected:
            if expected.detector not in ("confidentiality_label", "custom:corpus-keywords"):
                assert expected.value not in doc.name
                assert expected.value not in repr(expected)


def test_bank_accounts_with_a_listed_code_pair_reach_high(corpus: list[Document]) -> None:
    # [DLP] 4.4 (#146): a valid bank and branch code pair nearby, or in the row, makes an account
    # high; a pair that isn't on the list leaves it medium. Measured on the corpus's own list,
    # since nothing real is bundled yet, by distinct value per document as the scorer counts.
    outcomes: Counter[tuple[str, str]] = Counter()
    for doc in corpus:
        labelled = [e for e in doc.expected if e.detector == "jp_bank_account"]
        if not labelled or not doc.name.startswith("jp_bank_account/positives/"):
            continue
        scanner = _Scanner([], BANK_CODES)
        for unit in doc.units:
            scanner.feed(unit)
        scanner.findings()
        tally = scanner._tallies.get("jp_bank_account")
        reported = tally.values if tally is not None else {}
        for expected in labelled:
            got = reported.get(scanner._digest(expected.value))
            outcomes[(expected.confidence, "high" if got == 2 else "not high")] += 1
    high, medium = outcomes[("high", "high")], outcomes[("medium", "high")]
    assert outcomes[("high", "high")] + outcomes[("high", "not high")] >= 100, outcomes
    assert high / (high + outcomes[("high", "not high")]) >= 0.90, outcomes  # recall at high
    assert high / (high + medium) >= 0.90, outcomes  # precision at high
