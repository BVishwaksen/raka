class MemorySink:
    """Keeps events in a list. Handy for tests and the red-team harness."""

    def __init__(self):
        self.events: list[dict] = []

    def write(self, event: dict) -> None:
        self.events.append(event)

    def clear(self) -> None:
        self.events.clear()
