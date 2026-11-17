import pytest

from app import app as flask_app


@pytest.fixture()
def client():
    flask_app.config.update(TESTING=True)
    return flask_app.test_client()


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_users_returns_single_user(client):
    resp = client.get("/users?id=2")
    assert resp.status_code == 200
    assert resp.get_json() == [{"id": 2, "name": "bob", "role": "user"}]


def test_users_sql_injection_is_present(client):
    """Documents the planted SQLi: a tautology returns every user."""
    resp = client.get("/users?id=1 OR 1=1")
    assert len(resp.get_json()) == 3


def test_hash_md5(client):
    resp = client.get("/hash?value=abc")
    assert resp.get_json()["md5"] == "900150983cd24fb0d6963f7d28e17f72"
