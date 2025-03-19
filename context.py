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

    def __str__(self):
        str = ""
        if self.plaintext: str += f"p: {self.plaintext} "
        if self.plain_words: str += f"pw: {self.plain_words} "
        if self.plain_pfx: str += f"pp: {self.plain_pfx} "
        if self.key_words: str += f"kw: {self.key_words} "
        if self.key_pfx: str += f"kp: {self.key_pfx} "
        str += f"c: {self.cipher} f: {self.fragments}"
        return str

    def print(self, hdr=None):
        if hdr: print(hdr)
        print(self)
