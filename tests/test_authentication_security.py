import os
import tempfile

import pytest

from run import app, bcrypt


@pytest.fixture
def client(monkeypatch):
    temp_users_fd, temp_users_path = tempfile.mkstemp()
    temp_scores_fd, temp_scores_path = tempfile.mkstemp()

    monkeypatch.setattr("run.USERS_FILE", temp_users_path)
    monkeypatch.setattr("run.SCORES_FILE", temp_scores_path)

    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SECRET_KEY="test-secret-key"
    )

    with app.test_client() as client:
        with app.app_context():
            yield client

    os.close(temp_users_fd)
    os.unlink(temp_users_path)

    os.close(temp_scores_fd)
    os.unlink(temp_scores_path)


@pytest.fixture
def csrf_client(monkeypatch):
    temp_users_fd, temp_users_path = tempfile.mkstemp()
    temp_scores_fd, temp_scores_path = tempfile.mkstemp()

    monkeypatch.setattr("run.USERS_FILE", temp_users_path)
    monkeypatch.setattr("run.SCORES_FILE", temp_scores_path)

    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=True,
        SECRET_KEY="test-secret-key"
    )

    with app.test_client() as client:
        with app.app_context():
            yield client

    os.close(temp_users_fd)
    os.unlink(temp_users_path)

    os.close(temp_scores_fd)
    os.unlink(temp_scores_path)


def write_test_user(path, username, password, role="user", cur_score=0, high_score=0):
    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    with open(path, "a") as f:
        f.write(f"{username}:{password_hash}:{role}:{cur_score}:{high_score}\n")


def test_password_is_hashed_after_registration(client):
    client.post("/register", data={
        "username": "secureuser",
        "password": "password123",
        "confirm_password": "password123"
    })

    from run import USERS_FILE

    with open(USERS_FILE, "r") as f:
        stored_data = f.read()

    assert "password123" not in stored_data
    assert "secureuser:" in stored_data
    assert "$2" in stored_data


def test_invalid_username_is_rejected(client):
    response = client.post("/register", data={
        "username": "../baduser",
        "password": "password123",
        "confirm_password": "password123"
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Username must be" in response.data


def test_normal_user_cannot_access_admin(client):
    from run import USERS_FILE

    write_test_user(USERS_FILE, "normaluser", "password123", "user")

    client.post("/login", data={
        "username": "normaluser",
        "password": "password123"
    })

    response = client.get("/admin")

    assert response.status_code == 403
    assert b"You do not have permission" in response.data


def test_admin_can_access_admin_page(client):
    from run import USERS_FILE

    write_test_user(USERS_FILE, "adminuser", "password123", "admin")

    client.post("/login", data={
        "username": "adminuser",
        "password": "password123"
    })

    response = client.get("/admin")

    assert response.status_code == 200
    assert b"Admin" in response.data


def test_profile_requires_login(client):
    response = client.get("/profile", follow_redirects=False)

    assert response.status_code in (302, 401)


def test_csrf_blocks_register_without_token(csrf_client):
    response = csrf_client.post("/register", data={
        "username": "csrfuser",
        "password": "password123",
        "confirm_password": "password123"
    })

    assert response.status_code == 400


def test_logged_in_user_can_view_previous_scores(client):
    from run import USERS_FILE, SCORES_FILE

    write_test_user(USERS_FILE, "scoreuser", "password123", "user", high_score=12)

    with open(SCORES_FILE, "a") as f:
        f.write("scoreuser:5\n")
        f.write("scoreuser:12\n")

    client.post("/login", data={
        "username": "scoreuser",
        "password": "password123"
    })

    response = client.get("/profile")

    assert response.status_code == 200
    assert b"Previous Scores" in response.data
    assert b"Score: 5" in response.data
    assert b"Score: 12" in response.data


def test_score_share_page_is_public(client):
    from run import USERS_FILE, SCORES_FILE

    write_test_user(USERS_FILE, "shareuser", "password123", "user", high_score=18)

    with open(SCORES_FILE, "a") as f:
        f.write("shareuser:18\n")

    response = client.get("/share/shareuser")

    assert response.status_code == 200
    assert b"shareuser" in response.data
    assert b"High Score" in response.data
    assert b"Score: 18" in response.data

def test_admin_can_delete_unregistered_score_content(client):
    from run import USERS_FILE, SCORES_FILE

    write_test_user(USERS_FILE, "adminuser", "password123", "admin")

    with open(SCORES_FILE, "a") as f:
        f.write("guestuser:10\n")

    client.post("/login", data={
        "username": "adminuser",
        "password": "password123"
    })

    response = client.post("/admin", data={
        "action": "delete",
        "username": "guestuser"
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"User content deleted" in response.data

    with open(SCORES_FILE, "r") as f:
        stored_scores = f.read()

    assert "guestuser" not in stored_scores