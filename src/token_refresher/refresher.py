import os
import time
import json
import base64
import datetime
import logging
import threading
import requests

logger = logging.getLogger('stock_analysis.refresher')


class Value:
    """Thread-safe value holder with the same interface as multiprocessing.Value.

    Wraps reads and writes to `.value` in a threading.Lock, making it safe
    for use when refresh_token is run in a Thread. For use with a Process,
    pass a multiprocessing.Value instead.
    """
    def __init__(self, initial=None):
        self._lock = threading.Lock()
        self._value = initial

    @property
    def value(self):
        with self._lock:
            return self._value

    @value.setter
    def value(self, v):
        with self._lock:
            self._value = v


def _load_token_file(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    with open(path, 'r') as f:
        data = json.load(f)
    return data


def refresh_token(token_file_path, value):
    """
    Continuously monitor and refresh an OAuth2 access token stored in `token_file_path`.

    Parameters
    - token_file_path: path to JSON token file
    - value: a multiprocessing.Value or token_refresher.Value instance used to
             deliver the current access token to consumers via its `.value` attribute.
             Set to None when the refresh token has expired or all refresh attempts fail.

    Behavior (summary):
    - If current time > refresh_token_expiration_timestamp: set value.value = None and exit.
    - If current time < expiration_timestamp: set value.value = access_token and sleep until expiration.
    - If current time >= expiration_timestamp: use the refresh token to request a new access token
      and set value.value to the new access_token. On total failure, set value.value = None and exit.

    Note: For testability, if environment variable `REFRESH_TOKEN_RUN_ONCE` is set to '1', the function
    will perform a single iteration and return.
    """
    def _to_dt(v):
        # Accept ISO strings (with or without 'Z'), datetime objects, or numeric timestamps
        if isinstance(v, datetime.datetime):
            return v
        if isinstance(v, (int, float)):
            return datetime.datetime.fromtimestamp(v)
        if isinstance(v, str):
            s = v
            if s.endswith('Z'):
                s = s[:-1]
            try:
                return datetime.datetime.fromisoformat(s)
            except Exception:
                # try parsing as float seconds since epoch
                try:
                    return datetime.datetime.fromtimestamp(float(v))
                except Exception:
                    raise ValueError('Invalid timestamp')
        raise ValueError('Invalid timestamp')

    logger.debug("entering refresh_token for %s", token_file_path)

    # Main loop - keep running until parent kills the thread/process
    while True:
        # Reload token data each iteration so we pick up any external edits
        try:
            token_data = _load_token_file(token_file_path)
        except Exception:
            logger.exception("Failed to load token file: %s", token_file_path)
            raise

        # Validate required fields
        for fld in ('access_token', 'refresh_token', 'expiration_timestamp', 'refresh_token_expiration_timestamp', 'client_id', 'client_secret'):
            if fld not in token_data:
                raise ValueError(f"Missing required field in token data: {fld}")

        now = datetime.datetime.now()
        exp_ts = _to_dt(token_data['expiration_timestamp'])
        refresh_exp_ts = _to_dt(token_data['refresh_token_expiration_timestamp'])

        # If refresh token has expired, set None sentinel and exit
        if now > refresh_exp_ts:
            logger.info("refresh token expired (%s) — setting value to None and exiting", refresh_exp_ts)
            value.value = None
            return

        # If access token is still valid, publish it and sleep until expiry
        if now < exp_ts:
            logger.info("access token still valid until %s — publishing token", exp_ts)
            logger.debug("setting value to current access_token")
            value.value = token_data['access_token']
            if os.getenv('REFRESH_TOKEN_RUN_ONCE') == '1':
                return
            # Sleep until expiration (or at least 1 second)
            sleep_seconds = max(1, (exp_ts - now).total_seconds())
            time.sleep(sleep_seconds)
            continue

        # Otherwise, refresh the token
        client_id = token_data['client_id']
        client_secret = token_data['client_secret']
        refresh_token_val = token_data['refresh_token']

        headers = {
            'Authorization': 'Basic ' + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode(),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'refresh_token': refresh_token_val,
            'grant_type': 'refresh_token'
        }

        # Try refresh up to 3 times on transient failures
        attempts = 0
        success = False
        last_exception = None
        while attempts < 3 and not success:
            try:
                logger.info("attempting token refresh (attempt %d)", attempts + 1)
                resp = requests.post('https://api.schwabapi.com/v1/oauth/token', headers=headers, data=data)
                resp.raise_for_status()
                new_token = resp.json()
                logger.debug("refresh response: %s", new_token)

                # Update token_data with new values
                token_data['access_token'] = new_token.get('access_token')
                if 'refresh_token' in new_token:
                    token_data['refresh_token'] = new_token['refresh_token']
                expires_in = int(new_token.get('expires_in', 0))
                token_data['expiration_timestamp'] = (datetime.datetime.now() + datetime.timedelta(seconds=expires_in)).isoformat()
                # Keep existing refresh expiration unless response provides one
                if 'refresh_token_expires_in' in new_token:
                    rt_expires = int(new_token['refresh_token_expires_in'])
                    token_data['refresh_token_expiration_timestamp'] = (datetime.datetime.now() + datetime.timedelta(seconds=rt_expires)).isoformat()

                # Publish new access token
                logger.info("setting value to refreshed access token")
                value.value = token_data['access_token']

                success = True
                break
            except Exception as e:
                last_exception = e
                attempts += 1
                logger.exception("token refresh attempt %d failed", attempts)
                time.sleep(5)

        if not success:
            # All retries failed — set None sentinel and exit
            logger.error("Token refresh failed after %d attempts: %s", attempts, last_exception)
            value.value = None
            return

        if os.getenv('REFRESH_TOKEN_RUN_ONCE') == '1':
            logger.debug("REFRESH_TOKEN_RUN_ONCE set — exiting after single run")
            return

        # Otherwise, sleep until new expiration and loop
        now2 = datetime.datetime.now()
        exp_ts2 = datetime.datetime.fromisoformat(token_data['expiration_timestamp'])
        sleep_seconds = max(1, (exp_ts2 - now2).total_seconds())
        time.sleep(sleep_seconds)
        continue
