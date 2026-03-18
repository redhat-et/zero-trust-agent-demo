"""URL extraction, S3 conversion, document fetching, and review."""

import re
from urllib.parse import urlparse

import httpx

from llm import (
    get_provider,
    REVIEWER_SYSTEM_PROMPT,
    REVIEWER_COMPLIANCE_PROMPT,
    REVIEWER_SECURITY_PROMPT,
)


_URL_PATTERN = re.compile(r"(s3://[^\s]+|https?://[^\s]+)")


def extract_url(text: str) -> str | None:
    """Extract the first S3 or HTTP(S) URL from the given text."""
    match = _URL_PATTERN.search(text)
    return match.group(1) if match else None


def s3_to_https(url: str) -> str:
    """Convert an s3:// URL to an HTTPS virtual-hosted-style URL.

    If the URL is not an S3 URL, return it unchanged.
    """
    if not url.startswith("s3://"):
        return url

    parsed = urlparse(url)
    bucket = parsed.netloc
    key = parsed.path.lstrip("/")
    return f"https://{bucket}.s3.amazonaws.com/{key}"


async def fetch_document(url: str) -> str:
    """Fetch a document from a URL and return its text content."""
    async with httpx.AsyncClient() as client:
        response = await client.get(url, follow_redirects=True)
        response.raise_for_status()
        return response.text


def extract_review_type(text: str) -> str:
    """Determine the review type from the message text.

    Looks for 'compliance' or 'security' keywords; defaults to 'general'.
    """
    lower = text.lower()
    if "compliance" in lower:
        return "compliance"
    if "security" in lower:
        return "security"
    return "general"


def get_review_prompt(review_type: str) -> str:
    """Return the appropriate system prompt for the given review type."""
    prompts = {
        "compliance": REVIEWER_COMPLIANCE_PROMPT,
        "security": REVIEWER_SECURITY_PROMPT,
        "general": REVIEWER_SYSTEM_PROMPT,
    }
    return prompts.get(review_type, REVIEWER_SYSTEM_PROMPT)


async def fetch_and_review(message: str) -> str:
    """Extract a URL from the message, fetch the document, and review it.

    Returns the review text or an error message if no URL is found.
    """
    url = extract_url(message)
    if url is None:
        return "No URL found in the message. Please provide an S3 or HTTPS URL."

    https_url = s3_to_https(url)
    content = await fetch_document(https_url)

    review_type = extract_review_type(message)
    system_prompt = get_review_prompt(review_type)

    provider = get_provider()
    review = provider.complete(system_prompt, content)
    return review
