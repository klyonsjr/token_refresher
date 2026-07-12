"""Tests for token_refresher.refresh_token."""
import datetime
import json
import os
from unittest.mock import MagicMock, patch

import pytest

from token_refresher import refresh_token, Value


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _future(seconds=3600):
    return (datetime.datetime.now() + datetime.timedelta(seconds=seconds)).isoformat()

def _past(seconds=3600):
    return (datetime.datetime.now() - datetime.timedelta(seconds=seconds)).isoformat()

def _make_token_file(tmp_path, **overrides):
    data = {
        "access_token": "access-abc",
        "refresh_token": "refresh-xyz",
        "expiration_timestamp": _future(3600),
        "refresh_token_expiration_timestamp": _future(7 * 24 * 3600),
        "client_id": "client123",
        "client_secret": "secret456",
    }
    data.update(overrides)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps(data))
    return str(token_file), data


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestValidTokenNoRefreshNeeded:
    def test_puts_access_token_in_value(self, tmp_path, monkeypatch):
        monkeypatch.setenv("REFRESH_TOKEN_RUN_ONCE", "1")
        token_path, data = _make_token_file(tmp_path)
        v = Value()

        refresh_token(token_path, v)

        assert v.value == data["access_token"]


class TestRefreshTokenExpired:
    def test_sets_none_when_refresh_token_expired(self, tmp_path):
        token_path, _ = _make_token_file(
            tmp_path,
            refresh_token_expiration_timestamp=_past(1),
        )
        v = Value()

        refresh_token(token_path, v)

        assert v.value is None


class TestAccessTokenExpiredRefreshSucceeds:
    def _mock_response(self, payload, status_code=200):
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.json.return_value = payload
        if status_code >= 400:
            from requests import HTTPError
            mock_resp.raise_for_status.side_effect = HTTPError(response=mock_resp)
        else:
            mock_resp.raise_for_status.return_value = None
        return mock_resp

    def test_calls_api_and_sets_new_token(self, tmp_path, monkeypatch):
        monkeypatch.setenv("REFRESH_TOKEN_RUN_ONCE", "1")
        monkeypatch.setattr("time.sleep", lambda _: None)
        token_path, _ = _make_token_file(
            tmp_path,
            expiration_timestamp=_past(60),
        )
        new_access_token = "new-access-token-999"
        mock_resp = self._mock_response({"access_token": new_access_token, "expires_in": 1800})
        v = Value()

        with patch("token_refresher.refresher.requests.post", return_value=mock_resp):
            refresh_token(token_path, v)

        assert v.value == new_access_token


class TestTransientFailureRetry:
    def _mock_response(self, payload=None, status_code=200):
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        if payload:
            mock_resp.json.return_value = payload
        if status_code >= 400:
            from requests import HTTPError
            mock_resp.raise_for_status.side_effect = HTTPError(response=mock_resp)
        else:
            mock_resp.raise_for_status.return_value = None
        return mock_resp

    def test_retries_on_http_error_then_succeeds(self, tmp_path, monkeypatch):
        monkeypatch.setenv("REFRESH_TOKEN_RUN_ONCE", "1")
        monkeypatch.setattr("time.sleep", lambda _: None)
        token_path, _ = _make_token_file(
            tmp_path,
            expiration_timestamp=_past(60),
        )
        fail = self._mock_response(status_code=503)
        ok = self._mock_response(payload={"access_token": "retry-token", "expires_in": 1800})
        v = Value()

        with patch("token_refresher.refresher.requests.post", side_effect=[fail, ok]):
            refresh_token(token_path, v)

        assert v.value == "retry-token"

    def test_sets_none_after_all_retries_fail(self, tmp_path, monkeypatch):
        monkeypatch.setenv("REFRESH_TOKEN_RUN_ONCE", "1")
        monkeypatch.setattr("time.sleep", lambda _: None)
        token_path, _ = _make_token_file(
            tmp_path,
            expiration_timestamp=_past(60),
        )
        fail = self._mock_response(status_code=500)
        v = Value()

        with patch("token_refresher.refresher.requests.post", side_effect=[fail, fail, fail]):
            refresh_token(token_path, v)

        assert v.value is None


class TestMissingRequiredFields:
    @pytest.mark.parametrize("missing_field", [
        "access_token",
        "refresh_token",
        "expiration_timestamp",
        "refresh_token_expiration_timestamp",
        "client_id",
        "client_secret",
    ])
    def test_raises_value_error_for_missing_field(self, tmp_path, missing_field):
        token_path, data = _make_token_file(tmp_path)
        loaded = json.loads(open(token_path).read())
        del loaded[missing_field]
        open(token_path, "w").write(json.dumps(loaded))

        v = Value()
        with pytest.raises(ValueError, match="Missing required field"):
            refresh_token(token_path, v)


class TestFileNotFound:
    def test_raises_file_not_found(self, tmp_path):
        v = Value()
        with pytest.raises(FileNotFoundError):
            refresh_token(str(tmp_path / "nonexistent.json"), v)


class TestTimestampFormats:
    @pytest.mark.parametrize("ts_format", [
        lambda: _future(3600),                                       # ISO string
        lambda: _future(3600) + "Z",                                 # ISO with Z
        lambda: (datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp(),  # numeric
    ])
    def test_accepts_various_timestamp_formats(self, tmp_path, monkeypatch, ts_format):
        monkeypatch.setenv("REFRESH_TOKEN_RUN_ONCE", "1")
        token_path, _ = _make_token_file(
            tmp_path,
            expiration_timestamp=ts_format(),
            refresh_token_expiration_timestamp=ts_format(),
        )
        v = Value()
        # Should not raise
        refresh_token(token_path, v)
