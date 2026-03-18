import pytest
from reviewer import extract_url, s3_to_https, extract_review_type


def test_extract_s3_url():
    msg = "Please review s3://my-bucket/docs/report.md"
    assert extract_url(msg) == "s3://my-bucket/docs/report.md"


def test_extract_https_url():
    msg = "Review https://example.com/doc.md please"
    assert extract_url(msg) == "https://example.com/doc.md"


def test_extract_url_none():
    assert extract_url("no url here") is None


def test_s3_to_https():
    result = s3_to_https("s3://my-bucket/path/doc.md")
    assert result == "https://my-bucket.s3.amazonaws.com/path/doc.md"


def test_s3_to_https_passthrough():
    url = "https://example.com/doc.md"
    assert s3_to_https(url) == url


def test_extract_review_type_compliance():
    assert extract_review_type("Do a compliance review of this doc") == "compliance"


def test_extract_review_type_security():
    assert extract_review_type("Run a security check on this") == "security"


def test_extract_review_type_general():
    assert extract_review_type("Review this document please") == "general"
