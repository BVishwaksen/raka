import json


class PostgresSink:
    """Install with ``pip install agentguard[postgres]``."""

    def __init__(self, dsn: str, table: str = "agentguard_events"):
        import psycopg  # lazy: extra dependency
        if not table.replace("_", "").isalnum():
            raise ValueError("invalid table name")
        self._table = table
        self._conn = psycopg.connect(dsn, autocommit=True)
        self._conn.execute(
            f"CREATE TABLE IF NOT EXISTS {table} (id BIGSERIAL PRIMARY KEY, "
            "ts TIMESTAMPTZ NOT NULL DEFAULT now(), event JSONB NOT NULL)")

    def write(self, event: dict) -> None:
        self._conn.execute(f"INSERT INTO {self._table} (event) VALUES (%s)", (json.dumps(event, default=str),))
