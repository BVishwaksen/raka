from typing import Protocol


class Sink(Protocol):
    def write(self, event: dict) -> None: ...
