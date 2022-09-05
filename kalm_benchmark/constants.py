from enum import Enum, auto
from typing import Generator


class UpdateType(Enum):
    Info = auto()
    Warning = auto()
    Error = auto()
    Progress = auto()


RunUpdateGenerator = Generator[tuple[UpdateType, str], None, list | dict | None]
