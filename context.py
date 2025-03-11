from dataclasses import dataclass, field
from typing import Optional, List

@dataclass
class Pkc:
    plaintext: str = ""
    key: str = ""
    cipher: str = ""

@dataclass
class Context(Pkc):
    level: int = 0
    once: bool = False
    fragments: List[str] = None
    plaintext: Optional[str] = None
    plain_words: Optional[List[str]] = None
    plain_pfx: Optional[str] = None
    key_words: Optional[List[str]] = None
    key_pfx: Optional[str] = None
    key_sfx: Optional[str] = None
    pkc: Pkc = field(default_factory=Pkc)

