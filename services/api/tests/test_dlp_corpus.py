"""NFR-25 on the synthetic corpus ([DLP] section 8): each detector meets its precision and recall.

About 20,000 documents on every run. Set DLP_CORPUS_SCALE=10 for the nightly run of about 200,000.
Failure messages name detectors, layouts, documents and counts, never a value.
"""

import os
from collections import Counter

import pytest

from dlp_corpus.generate import DETECTORS, Document, generate_corpus, keyword_list
from dlp_corpus.score import TARGETS, failures, score, table
from sft.dlp.detect import BUILTIN_DETECTORS


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
