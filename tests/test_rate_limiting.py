"""
Task 9 - Security tests for rate limiting (Feature 1).

Each test maps to a security requirement from Task 8 Feature 1 design.
Sources: Flask-Limiter documentation (https://flask-limiter.readthedocs.io/)
"""

import pytest

from run import app, limiter


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Clear in-memory counters between tests."""
    limiter.reset()
    app.config["TESTING"] = True
    yield
    limiter.reset()


@pytest.fixture
def client():
    with app.test_client() as test_client:
        yield test_client


def test_post_index_allows_requests_under_limit(client):
    """
    Requirement RL-01 (Availability): normal use stays under the POST / limit.
    """
    for i in range(5):
        response = client.post("/", data={"username": f"player{i}"})
        assert response.status_code in (200, 302)


def test_post_index_blocks_excessive_requests(client):
    """
    Requirement RL-02 (Availability / DoS): flood of POST / requests is rejected.
    Evaluates OWASP denial-of-service mitigation from Task 3 code analysis.
    """
    statuses = []
    for i in range(12):
        response = client.post("/", data={"username": f"flood{i}"})
        statuses.append(response.status_code)

    assert 429 in statuses


def test_rate_limit_response_does_not_expose_internals(client):
    """
    Requirement RL-03 (Confidentiality): 429 page uses generic messaging.
    """
    for i in range(12):
        response = client.post("/", data={"username": f"probe{i}"})
        if response.status_code == 429:
            body = response.get_data(as_text=True)
            assert "memory://" not in body
            assert "per minute" not in body.lower()
            return

    pytest.fail("Expected at least one 429 response")


def test_rate_limit_includes_retry_headers(client):
    """
    Requirement RL-05 (Usability under attack): standard rate-limit headers are present.
    """
    for i in range(12):
        response = client.post("/", data={"username": f"header{i}"})
        if response.status_code == 429:
            assert "Retry-After" in response.headers or "X-RateLimit-Limit" in response.headers
            return

    pytest.fail("Expected at least one 429 response with rate-limit headers")
