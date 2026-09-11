"""Sonnet Lexicon: Syllable counter, Rhyme Extractor & DID Vocabulary Engine.

Filters CMUdict words strictly to characters available in an agent's DID,
indexes them by exact syllable counts, rhyme phonemes, and stress patterns.
"""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

WORD_RE = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)*")
TOKEN_RE = re.compile(r"([A-Za-z]+(?:'[A-Za-z]+)*)[,.;:!?]?")
VOWELS = {"AA", "AE", "AH", "AO", "AW", "AY", "EH", "ER", "EY", "IH", "IY", "OW", "OY", "UH", "UW"}
UPSTREAM_HASH = "81917843c7f44ce2b094ac63873c2c7a4cf802040792c455ba3ca406891c3d22"

_root_cmu = Path(__file__).resolve().parent / "cmudict.dict"
_sub_cmu = Path(__file__).resolve().parent / "technocore_sonnet" / "cmudict.dict"
DEFAULT_CMUDICT_PATH = _root_cmu if _root_cmu.exists() else _sub_cmu
DEFAULT_CACHE_DIR = Path(__file__).resolve().parent / ".sonnet_cache"


@dataclass(frozen=True)
class WordInfo:
    word: str
    syllables: int
    rhyme: str  # Base phonemes from last stressed vowel, e.g. "AY T"
    stress: str  # Stress digits e.g. "01", "10", "1"
    phones: Tuple[str, ...]


class SonnetLexicon:
    """Precomputed, high-performance vocabulary filtered by an agent's DID."""

    def __init__(
        self,
        did: str,
        cmudict_path: Path = DEFAULT_CMUDICT_PATH,
        cache_dir: Path = DEFAULT_CACHE_DIR,
    ):
        self.did = did.strip()
        self.allowed_letters = {c.lower() for c in self.did if c.isalpha()}
        self.cmudict_path = cmudict_path
        self.cache_dir = cache_dir

        self.words: Dict[str, WordInfo] = {}
        self.by_syllables: Dict[int, List[WordInfo]] = {}
        self.by_rhyme: Dict[str, List[WordInfo]] = {}
        self.by_rhyme_and_syllables: Dict[Tuple[str, int], List[WordInfo]] = {}

        self._load_or_build()

    def _cache_path(self) -> Path:
        did_hash = hashlib.sha256(self.did.encode("utf-8")).hexdigest()[:16]
        return self.cache_dir / f"lexicon_{did_hash}.pkl"

    def _load_or_build(self) -> None:
        cache_file = self._cache_path()
        if cache_file.exists():
            try:
                with open(cache_file, "rb") as f:
                    data = pickle.load(f)
                if data.get("upstream_hash") == UPSTREAM_HASH and data.get("did") == self.did:
                    self.words = data["words"]
                    self.by_syllables = data["by_syllables"]
                    self.by_rhyme = data["by_rhyme"]
                    self.by_rhyme_and_syllables = data["by_rhyme_and_syllables"]
                    return
            except Exception:
                pass  # Fall back to rebuilding

        self._build_index()

    def _build_index(self) -> None:
        if not self.cmudict_path.is_file():
            try:
                import urllib.request
                url = "https://raw.githubusercontent.com/flop-labs/technocore-sonnet-challenge/main/cmudict.dict"
                self.cmudict_path.parent.mkdir(parents=True, exist_ok=True)
                urllib.request.urlretrieve(url, str(self.cmudict_path))
            except Exception as e:
                raise FileNotFoundError(f"CMUdict not found at {self.cmudict_path} and download failed: {e}")

        raw_bytes = self.cmudict_path.read_bytes()
        actual_hash = hashlib.sha256(raw_bytes).hexdigest()
        if actual_hash != UPSTREAM_HASH:
            raise ValueError(
                f"CMUdict hash mismatch: expected {UPSTREAM_HASH}, got {actual_hash}"
            )

        # CMUdict can list multiple pronunciations per word:
        # Rule: "charging the largest listed syllable count when pronunciations differ."
        word_entries: Dict[str, List[Tuple[List[str], int, str, str]]] = {}

        for line in raw_bytes.decode("utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith(";;;"):
                continue
            fields = line.split()
            raw_word = re.sub(r"\(\d+\)$", "", fields[0]).lower()
            if not WORD_RE.fullmatch(raw_word):
                continue

            # Strict DID letter constraint (apostrophes are exempt per contest rules)
            word_letters = {c for c in raw_word if c.isalpha()}
            if not word_letters.issubset(self.allowed_letters):
                continue

            phones = fields[1:]
            # Syllable count: vowels with stress 0, 1, 2
            vowel_indices = [
                i for i, p in enumerate(phones)
                if p[:-1] in VOWELS and p[-1:] in {"0", "1", "2"}
            ]
            count = len(vowel_indices)
            if count == 0:
                continue

            # Rhyme extraction: from last stressed vowel (or last vowel if unstressed)
            last_stressed_idx = -1
            for vi in vowel_indices:
                if phones[vi][-1] in {"1", "2"} or last_stressed_idx == -1:
                    last_stressed_idx = vi

            base_vowel = phones[last_stressed_idx][:-1]
            tail = [p[:-1] if p[:-1] in VOWELS else p for p in phones[last_stressed_idx + 1:]]
            rhyme_key = " ".join([base_vowel] + tail)

            stress = "".join(phones[vi][-1] for vi in vowel_indices)

            if raw_word not in word_entries:
                word_entries[raw_word] = []
            word_entries[raw_word].append((phones, count, rhyme_key, stress))

        # Select the entry with maximum syllables for each word
        for word, entries in word_entries.items():
            best_entry = max(entries, key=lambda e: e[1])
            phones, count, rhyme_key, stress = best_entry

            info = WordInfo(
                word=word,
                syllables=count,
                rhyme=rhyme_key,
                stress=stress,
                phones=tuple(phones),
            )
            self.words[word] = info

            # Index by syllables
            if count not in self.by_syllables:
                self.by_syllables[count] = []
            self.by_syllables[count].append(info)

            # Index by rhyme
            if rhyme_key not in self.by_rhyme:
                self.by_rhyme[rhyme_key] = []
            self.by_rhyme[rhyme_key].append(info)

            # Index by (rhyme, syllables)
            pair_key = (rhyme_key, count)
            if pair_key not in self.by_rhyme_and_syllables:
                self.by_rhyme_and_syllables[pair_key] = []
            self.by_rhyme_and_syllables[pair_key].append(info)

        # Save cache
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        try:
            with open(self._cache_path(), "wb") as f:
                pickle.dump(
                    {
                        "upstream_hash": UPSTREAM_HASH,
                        "did": self.did,
                        "words": self.words,
                        "by_syllables": self.by_syllables,
                        "by_rhyme": self.by_rhyme,
                        "by_rhyme_and_syllables": self.by_rhyme_and_syllables,
                    },
                    f,
                )
        except Exception:
            pass

    def check_word(self, token: str) -> Tuple[bool, int, Optional[str], Optional[str]]:
        """Validates a single candidate token for our agent.
        Returns: (is_valid, syllables, rhyme_key, error_reason)
        """
        match = TOKEN_RE.fullmatch(token.strip())
        if not match:
            return False, 0, None, "Invalid token format"
        word = match.group(1).lower()

        # Strict DID letter check; apostrophes are exempt per upstream rules
        letters = {c for c in word if c.isalpha()}
        missing = letters - self.allowed_letters
        if missing:
            return False, 0, None, f"Letters not in DID: {''.join(sorted(missing))}"

        if word not in self.words:
            return False, 0, None, "Word not in dictionary"

        info = self.words[word]
        return True, info.syllables, info.rhyme, None

    def lookup_raw_cmu(self, token: str) -> Tuple[int, Optional[str]]:
        """Resolves syllables and rhyme for any English word from CMUdict (exempt from DID restriction).
        Used for parsing room words contributed by teammates.
        """
        match = TOKEN_RE.fullmatch(token.strip())
        if not match:
            return 0, None
        word = match.group(1).lower()
        if word in self.words:
            info = self.words[word]
            return info.syllables, info.rhyme
        
        # Load or cache raw dict lookup
        if not hasattr(self, "_raw_cmu"):
            try:
                from technocore_sonnet.sonnet_validate import read_lexicon
                self._raw_cmu = read_lexicon(self.cmudict_path)
            except Exception:
                self._raw_cmu = {}
                if self.cmudict_path.is_file():
                    for line in self.cmudict_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                        line = line.split("#", 1)[0].strip()
                        if not line or line.startswith(";;;"):
                            continue
                        f = line.split()
                        w = re.sub(r"\(\d+\)$", "", f[0]).lower()
                        c = sum(1 for p in f[1:] if p[:-1] in VOWELS and p[-1:] in {"0", "1", "2"})
                        if c > self._raw_cmu.get(w, 0):
                            self._raw_cmu[w] = c
        
        count = self._raw_cmu.get(word, 0)
        return count, None

    def get_rhyming_words(self, target_rhyme: str, syllables: Optional[int] = None) -> List[WordInfo]:
        """Returns words matching a given rhyme signature, optionally filtered by syllable count."""
        if syllables is not None:
            return self.by_rhyme_and_syllables.get((target_rhyme, syllables), [])
        return self.by_rhyme.get(target_rhyme, [])

    def get_candidates(
        self,
        syllables: int,
        target_rhyme: Optional[str] = None,
    ) -> List[WordInfo]:
        """Finds candidate words matching exact syllable count and optional target rhyme."""
        if target_rhyme:
            return self.by_rhyme_and_syllables.get((target_rhyme, syllables), [])
        return self.by_syllables.get(syllables, [])
