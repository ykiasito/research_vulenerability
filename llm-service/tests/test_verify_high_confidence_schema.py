"""Unit tests for the verify-high-confidence tool JSON schema (backlog item 9, senior review
2026-08-29, PR #5): ambiguous_candidates previously had no maxItems and its vendor/product/note
fields had no maxLength, so the only real bound on identified_products.verification_note (a TEXT
column with no DB-side length limit) was the model's own max_tokens. These tests pin the schema's
defensive caps directly, without making any real Claude API call.
"""

import importlib
import os
import sys

import pytest


@pytest.fixture(scope="module")
def main_module():
    # LOG_FILE="" disables main.py's RotatingFileHandler setup (which otherwise tries to create
    # /var/log/app on import) -- irrelevant to this test and not guaranteed writable in every
    # environment this suite runs in.
    os.environ.setdefault("LOG_FILE", "")
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return importlib.import_module("main")


def test_ambiguous_candidates_has_max_items_of_5(main_module):
    schema = main_module.VERIFY_HIGH_CONFIDENCE_SCHEMA
    ambiguous_candidates = schema["properties"]["ambiguous_candidates"]

    assert ambiguous_candidates["maxItems"] == 5


def test_ambiguous_candidate_string_fields_have_max_length_of_100(main_module):
    schema = main_module.VERIFY_HIGH_CONFIDENCE_SCHEMA
    candidate_properties = schema["properties"]["ambiguous_candidates"]["items"]["properties"]

    assert candidate_properties["vendor"]["maxLength"] == 100
    assert candidate_properties["product"]["maxLength"] == 100
    assert candidate_properties["note"]["maxLength"] == 100


def test_ambiguous_candidate_note_still_allows_null(main_module):
    # note is optional (an ambiguous candidate may have nothing distinguishing to say) -- adding
    # maxLength must not accidentally drop the "null" branch of its type union.
    schema = main_module.VERIFY_HIGH_CONFIDENCE_SCHEMA
    note_schema = schema["properties"]["ambiguous_candidates"]["items"]["properties"]["note"]

    assert set(note_schema["type"]) == {"string", "null"}


def test_ambiguous_candidate_items_still_require_vendor_product_and_note(main_module):
    # Regression guard: adding maxLength must not disturb the existing "required" list (vendor/
    # product/note must still all be present in every candidate object on the wire).
    schema = main_module.VERIFY_HIGH_CONFIDENCE_SCHEMA
    candidate_item_schema = schema["properties"]["ambiguous_candidates"]["items"]

    assert candidate_item_schema["required"] == ["vendor", "product", "note"]
    assert candidate_item_schema["additionalProperties"] is False


# REVISE (senior review 2026-08-30, PR #8): reasoning/alternative_vendor/alternative_product
# previously had no maxLength at all, unlike ambiguous_candidates above -- the only real bound on
# identified_products.verification_note built from these fields for the INCORRECT outcome (see
# HighConfidenceVerificationService#describeIncorrectVerdict) was the model's own max_tokens.


def test_reasoning_has_max_length_of_500(main_module):
    schema = main_module.VERIFY_HIGH_CONFIDENCE_SCHEMA
    reasoning_schema = schema["properties"]["reasoning"]

    assert reasoning_schema["maxLength"] == 500


def test_alternative_vendor_and_alternative_product_have_max_length_of_100(main_module):
    schema = main_module.VERIFY_HIGH_CONFIDENCE_SCHEMA
    properties = schema["properties"]

    assert properties["alternative_vendor"]["maxLength"] == 100
    assert properties["alternative_product"]["maxLength"] == 100


def test_alternative_vendor_and_alternative_product_still_allow_null(main_module):
    # Both are optional (only set when outcome='incorrect' and the model has a confident guess) --
    # adding maxLength must not accidentally drop the "null" branch of their type union.
    schema = main_module.VERIFY_HIGH_CONFIDENCE_SCHEMA
    properties = schema["properties"]

    assert set(properties["alternative_vendor"]["type"]) == {"string", "null"}
    assert set(properties["alternative_product"]["type"]) == {"string", "null"}
