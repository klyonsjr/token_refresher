# token-refresher

A pip-installable library that continuously monitors and refreshes a Schwab OAuth2 access token stored in a JSON file.

## Installation

```bash
pip install -e /path/to/token_refresher
```

Or from the repo root:

```bash
pip install -e ./token_refresher
```

## Usage

The library exposes a `Value` class and a `refresh_token` function. `Value` is a thread-safe value holder whose `.value` attribute holds the current access token string.

### With a thread (recommended)

```python
import threading
from token_refresher import refresh_token, Value

v = Value()
t = threading.Thread(target=refresh_token, args=("token.json", v), daemon=True)
t.start()

# Read the token whenever you need it
access_token = v.value
```

### With a process

`multiprocessing.Value` exposes the same `.value` interface and can be used instead when running `refresh_token` in a separate process:

```python
import multiprocessing
from token_refresher import refresh_token

v = multiprocessing.Value("c", b"")  # or any ctypes type that suits your token
p = multiprocessing.Process(target=refresh_token, args=("token.json", v), daemon=True)
p.start()

access_token = v.value
```

## Token file format

The token JSON file must contain the following fields:

```json
{
    "access_token": "...",
    "refresh_token": "...",
    "expiration_timestamp": "2026-01-01T00:00:00",
    "refresh_token_expiration_timestamp": "2026-01-07T00:00:00",
    "client_id": "...",
    "client_secret": "..."
}
```

Timestamps may be ISO 8601 strings (with or without trailing `Z`) or numeric Unix epoch values.

## Behaviour

- The current access token is published to `value.value` for consumers to read at any time.
- If the **refresh token** has expired, `value.value` is set to `None` and the function returns.
- If the **access token** is still valid, `value.value` is set to the current token and the function sleeps until it expires.
- If the **access token** has expired, a new one is requested from the Schwab API (up to 3 attempts). On success the token file is updated and `value.value` is set to the new token. On repeated failure `value.value` is set to `None` and the function returns.

## Environment variables

| Variable | Effect |
|---|---|
| `REFRESH_TOKEN_RUN_ONCE=1` | Perform a single iteration then return (useful for testing). |
