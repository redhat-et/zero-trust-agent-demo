"""URL extraction, S3 conversion, document fetching, and summarization."""

import re
from urllib.parse import urlparse

import httpx

from llm import get_provider, SUMMARIZER_SYSTEM_PROMPT


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
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, follow_redirects=True)
        response.raise_for_status()
        return response.text


async def fetch_and_summarize(message: str) -> str:
    """Extract a URL from the message, fetch the document, and summarize it.

    Returns the summary text or an error message if no URL is found.
    """
    url = extract_url(message)
    if url is None:
        return "No URL found in the message. Please provide an S3 or HTTPS URL."

    https_url = s3_to_https(url)
    content = await fetch_document(https_url)

    provider = get_provider()
    summary = provider.complete(SUMMARIZER_SYSTEM_PROMPT, content)
    return summary
