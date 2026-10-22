import json
import sys


class StdoutSink:
    def __init__(self, stream=None):
        self.stream = stream or sys.stdout

    def write(self, event: dict) -> None:
        self.stream.write(json.dumps(event, default=str) + "\n")
        self.stream.flush()
