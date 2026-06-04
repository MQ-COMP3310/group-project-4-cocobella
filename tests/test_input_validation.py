
# test_input_validation.py
# Task 9 - Security tests for Feature 2: Input Validation & Sanitisation.
# Run with: python -m pytest test_input_validation.py -v


import pytest
from run import app, limiter, validate_username, validate_answer, validate_riddle_index


@pytest.fixture(autouse=True)
def reset_limits():
    """Reset rate limits before each test."""
    limiter.reset()
    app.config["TESTING"] = True
    yield
    limiter.reset()


@pytest.fixture
def client():
    with app.test_client() as test_client:
        yield test_client


# --- Tests for validate_username() ---

def test_normal_username_is_accepted():
    """IV-01: A normal username like 'player1' should be accepted."""
    valid, error = validate_username("player1")
    assert valid is True


def test_empty_username_is_rejected():
    """IV-01: An empty username should be rejected."""
    valid, error = validate_username("")
    assert valid is False


def test_username_over_20_chars_is_rejected():
    """IV-02: A username longer than 20 characters should be rejected."""
    valid, error = validate_username("a" * 21)
    assert valid is False


def test_username_with_slash_is_rejected():
    """IV-03: A username with '/' should be rejected to prevent path traversal."""
    valid, error = validate_username("../secret")
    assert valid is False


def test_username_with_script_tag_is_rejected():
    """IV-03: A username with '<script>' should be rejected to prevent XSS."""
    valid, error = validate_username("<script>")
    assert valid is False


def test_username_with_spaces_is_rejected():
    """IV-01: A username with only spaces should be rejected."""
    valid, error = validate_username("   ")
    assert valid is False


# --- Tests for validate_answer() ---

def test_normal_answer_is_accepted():
    """IV-04: A normal answer like 'Water' should be accepted."""
    valid, result = validate_answer("Water")
    assert valid is True


def test_empty_answer_is_rejected():
    """IV-04: An empty answer should be rejected."""
    valid, result = validate_answer("")
    assert valid is False


def test_answer_over_50_chars_is_rejected():
    """IV-05: An answer longer than 50 characters should be rejected."""
    valid, result = validate_answer("a" * 51)
    assert valid is False


def test_answer_whitespace_is_stripped():
    """IV-04: Whitespace around an answer should be removed before saving."""
    valid, result = validate_answer("  River  ")
    assert valid is True
    assert result == "River"


# --- Tests for validate_riddle_index() ---

def test_valid_riddle_index_is_accepted():
    """IV-06: A valid index like 3 should be accepted."""
    valid, index = validate_riddle_index("3")
    assert valid is True
    assert index == 3


def test_negative_riddle_index_is_rejected():
    """IV-06: A negative index should be rejected and return 0 safely."""
    valid, index = validate_riddle_index("-1")
    assert valid is False
    assert index == 0


def test_out_of_range_riddle_index_is_rejected():
    """IV-06: An index like 999 should be rejected and return 0 safely."""
    valid, index = validate_riddle_index("999")
    assert valid is False
    assert index == 0


def test_non_number_riddle_index_is_rejected():
    """IV-06: A non-number like 'abc' should be rejected safely without crashing."""
    valid, index = validate_riddle_index("abc")
    assert valid is False
    assert index == 0


# --- Integration tests via the Flask app ---

def test_valid_username_redirects_to_welcome(client):
    """IV-01: A valid username on the homepage should redirect to the welcome page."""
    resp = client.post("/", data={"username": "alice"})
    assert resp.status_code == 302
    assert "alice" in resp.headers["Location"]


def test_empty_username_stays_on_homepage(client):
    """IV-01: An empty username should stay on the homepage with an error."""
    resp = client.post("/", data={"username": ""}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"alice" not in resp.data


def test_path_traversal_username_is_blocked(client):
    """IV-03: A path traversal username should be blocked at the homepage."""
    resp = client.post("/", data={"username": "../secret"}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"secret" not in resp.data