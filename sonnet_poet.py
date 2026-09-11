"""Sonnet Poet: Shakespearean Rhyme Resolver & Poetic Turn Generator.

Manages 14-line sonnet structure, 4/4/4/2 stanzas, 10-syllable line budgets,
7-family ABAB CDCD EFEF GG rhyme resolution, iambic meter scoring, and
word-frequency quality filtering.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from sonnet_lexicon import SonnetLexicon, WordInfo

# ---------------------------------------------------------------------------
# Shakespearean sonnet rhyme scheme: line index (0-based) -> family letter
# ---------------------------------------------------------------------------
LINE_RHYME_FAMILIES = [
    "A", "B", "A", "B",  # Quatrain 1
    "C", "D", "C", "D",  # Quatrain 2
    "E", "F", "E", "F",  # Quatrain 3
    "G", "G",            # Couplet
]

# ---------------------------------------------------------------------------
# Word-frequency gate (populated lazily by _ensure_freq_loaded)
# ---------------------------------------------------------------------------
_WORD_FREQ: Dict[str, float] = {}
_FREQ_LOADED = False

# Minimum frequency for a word to be considered "common English"
MIN_FREQ_RHYME = 5e-6     # End-of-line rhyme words must be at least this common
MIN_FREQ_MIDLINE = 1e-6   # Mid-line words can be slightly rarer
MIN_FREQ_FALLBACK = 1e-7  # Absolute floor for any word selection


def _ensure_freq_loaded(lexicon: SonnetLexicon) -> None:
    """Lazily loads word frequencies from wordfreq for every word in the lexicon."""
    global _WORD_FREQ, _FREQ_LOADED
    if _FREQ_LOADED:
        return
    try:
        from wordfreq import word_frequency
        for word in lexicon.words:
            _WORD_FREQ[word] = word_frequency(word, "en")
    except ImportError:
        # wordfreq not available — use empty dict (all words treated equally)
        pass
    _FREQ_LOADED = True


def word_freq(word: str) -> float:
    """Returns the wordfreq frequency of a word, or 0.0 if unknown."""
    return _WORD_FREQ.get(word.lower().rstrip(",.;:!?'"), 0.0)


# ---------------------------------------------------------------------------
# Curated Poetic Vocabulary — common, evocative, DID-verified words
# (All words verified to contain only: b,c,d,e,g,h,i,j,k,l,m,p,r,s,t,u,v,w,y,z)
# ---------------------------------------------------------------------------
POETIC_BANK = {
    "determiners": [
        "the", "this", "these", "thy", "their", "my", "his", "her", "its",
        "each", "every", "which", "such",
    ],
    "pronouns": [
        "we", "they", "he", "she", "it", "thee", "us", "them", "him",
        "her", "me", "i", "hers", "theirs",
    ],
    "prepositions": [
        "with", "by", "through", "beside", "till", "while", "up", "per",
        "mid", "like", "ere",
    ],
    "conjunctions": ["yet", "while", "till", "where", "which", "but", "is"],
    "adjectives": [
        # 1-syllable
        "bright", "light", "sweet", "pure", "true", "deep", "high", "wide",
        "still", "prime", "white", "clear", "rich", "wise", "blest",
        "bliss", "just", "sure", "wild", "mild", "dim", "thick", "silk",
        "swift", "crisp", "slim", "brisk", "mere", "shy", "wry", "grim",
        # 2-syllable
        "subtle", "silver", "bitter", "gentle", "humble", "simple",
        "purple", "secret", "merry", "witty", "lively", "vivid",
        "jester", "wicked", "supple", "sturdy", "mighty", "dusky",
        "misty", "guilty", "rugged", "bitter", "lusty", "empty",
        "clever", "pretty", "ugly", "little", "silent", "timid",
        "mystic", "sacred", "twisted", "rigid",
        # 3-syllable
        "beautiful", "precious", "glittery", "delightful", "wonderful",
        "terrible", "virtuous", "mysterious", "electric", "decisive",
        "exclusive", "elusive", "subjective", "respective",
    ],
    "nouns": [
        # 1-syllable
        "time", "rhyme", "verse", "light", "sight", "eyes", "sky",
        "breeze", "trees", "truth", "wit", "pride", "sleep", "peace",
        "hill", "well", "dew", "bell", "shell", "spell", "bride",
        "tide", "guide", "guest", "rest", "mist", "dusk", "dust",
        "vice", "price", "ice", "gust", "bliss", "jest", "zest",
        "rite", "mirth", "birth", "grip", "will", "skill",
        "steel", "wheel", "jewel", "prize", "crest", "quest",
        "kiss", "wish", "bird", "girl", "curve", "cup", "seed",
        "weed", "speed", "creek", "cheek", "week", "street",
        "trick", "lip", "tip", "whip", "ship", "trip",
        # 2-syllable
        "summer", "spirit", "river", "city", "music", "desire",
        "delight", "decree", "secret", "whisper", "mercy",
        "virtue", "mystery", "liberty", "cricket", "slumber",
        "shimmer", "glimmer", "twilight", "silver", "velvet",
        "triumph", "empire", "glimpse", "riddle", "puzzle",
        "sunrise", "device", "service", "muscle", "hustle",
        "temple", "jewel", "pencil", "devil", "level",
        "vessel", "missile", "thistle", "whistle", "buckle",
        "beetle", "ripple", "drizzle", "sizzle", "puzzle",
        # 3-syllable
        "destiny", "liberty", "mystery", "victory", "dignity",
        "eternity", "industry", "energy", "delivery", "discovery",
        "reverie", "cemetery", "chemistry", "lullaby",
    ],
    "verbs": [
        # 1-syllable
        "is", "will", "must", "might", "see", "seek", "tell",
        "write", "rise", "weep", "sleep", "rest", "bide", "hide",
        "glide", "guide", "gleam", "bring", "keep", "meet",
        "greet", "bless", "press", "yield", "build", "give", "live",
        "try", "cry", "die", "lie", "dry", "buy", "spy",
        "set", "get", "let", "sit", "hit", "bit", "split",
        "cut", "shut", "put", "dig", "swim", "trip", "drip",
        "drift", "shift", "twist", "grip", "kiss", "miss",
        "wish", "push", "rush", "hush", "blush", "crush",
        # 2-syllable
        "believe", "receive", "perceive", "deceive", "achieve",
        "retrieve", "derive", "survive", "revive", "deprive",
        "beguile", "beseech", "bestir", "betide", "dispel",
        "distill", "disturb", "divert", "divide", "emerge",
        "persist", "preserve", "pursue", "resist", "revere",
        "whisper", "shimmer", "glimmer", "tremble", "stumble",
        "crumble", "tumble", "murmur", "slumber", "wither",
        "deliver", "discover", "remember", "surrender",
        "provide", "depict", "predict", "restrict", "submit",
        "eclipse", "dismiss", "bewilder",
    ],
    "adverbs": [
        "still", "yet", "well", "here", "there", "thus", "erst",
        "deeply", "sweetly", "brightly", "purely", "truly",
        "gently", "simply", "swiftly", "merely", "directly",
        "widely", "highly", "richly", "dimly", "slightly",
    ],
}


# ---------------------------------------------------------------------------
# Poem State
# ---------------------------------------------------------------------------
@dataclass
class PoemState:
    lines: List[str] = field(default_factory=list)
    current_tokens: List[str] = field(default_factory=list)
    current_syllables: int = 0
    current_stress: str = ""  # accumulated stress digits for current line
    rhyme_sounds: Dict[str, str] = field(default_factory=dict)
    used_rhyme_sounds: Set[str] = field(default_factory=set)
    used_words: Set[str] = field(default_factory=set)  # repetition tracker

    @property
    def line_index(self) -> int:
        return len(self.lines)

    @property
    def is_finished(self) -> bool:
        return len(self.lines) >= 14

    @property
    def remaining_syllables(self) -> int:
        return 10 - self.current_syllables


# ---------------------------------------------------------------------------
# Sonnet Poet
# ---------------------------------------------------------------------------
class SonnetPoet:
    """Intelligent agentic poet that composes strictly compliant Sonnets."""

    def __init__(self, lexicon: SonnetLexicon):
        self.lexicon = lexicon
        _ensure_freq_loaded(lexicon)

        # Filter poetic bank strictly through lexicon
        self.curated_words: Dict[str, List[WordInfo]] = {}
        self.curated_set: Set[str] = set()
        for category, words in POETIC_BANK.items():
            valid_infos = []
            for w in words:
                ok, syl, rhyme, _ = self.lexicon.check_word(w)
                if ok and w in self.lexicon.words:
                    valid_infos.append(self.lexicon.words[w])
                    self.curated_set.add(w)
            self.curated_words[category] = valid_infos

    # ------------------------------------------------------------------
    # Streaming poem parser (handles room word stream)
    # ------------------------------------------------------------------
    def parse_poem_text(self, text: str) -> PoemState:
        """Parses a poem string (either newline-separated or a continuous
        space-separated stream of words).  Maintains a running 10-syllable
        accumulator to partition lines accurately.  Resolves teammate words
        via raw CMUdict so syllables and rhyme sounds are preserved.
        """
        state = PoemState()
        tokens = text.strip().split()
        for token in tokens:
            if state.is_finished:
                break

            syl, rhyme = self.lexicon.lookup_raw_cmu(token)
            if syl <= 0:
                continue

            if state.current_syllables + syl <= 10:
                state.current_tokens.append(token)
                state.current_syllables += syl
                state.used_words.add(token.lower().rstrip(",.;:!?"))

                if state.current_syllables == 10:
                    self._close_line(state, rhyme)
            else:
                # Syllable overflow: start next line
                if state.current_tokens:
                    state.lines.append(" ".join(state.current_tokens))
                    state.current_tokens = [token]
                    state.current_syllables = syl
                    state.current_stress = ""
                    state.used_words.add(token.lower().rstrip(",.;:!?"))
                if len(state.lines) >= 14:
                    break

        return state

    def _close_line(self, state: PoemState, end_rhyme: Optional[str] = None) -> None:
        """Finalizes a completed 10-syllable line."""
        completed_line = " ".join(state.current_tokens)
        line_num = len(state.lines)

        # Extract line-ending rhyme sound
        if end_rhyme is None:
            _, end_rhyme = self.lexicon.lookup_raw_cmu(state.current_tokens[-1])
        if end_rhyme and line_num < len(LINE_RHYME_FAMILIES):
            family = LINE_RHYME_FAMILIES[line_num]
            if family not in state.rhyme_sounds:
                state.rhyme_sounds[family] = end_rhyme
                state.used_rhyme_sounds.add(end_rhyme)

        state.lines.append(completed_line)
        state.current_tokens = []
        state.current_syllables = 0
        state.current_stress = ""

    # ------------------------------------------------------------------
    # Word quality filters
    # ------------------------------------------------------------------
    @staticmethod
    def _is_lyrical(word_info: WordInfo) -> bool:
        """Filters out acronyms, brands, profanity, and consonant clusters."""
        w = word_info.word.lower()
        # Must contain vowels (e, i, u, y for our DID; also check a, o for general)
        if not any(c in "aeiouy" for c in w):
            return False
        # Profanity / vulgar filter
        _VULGAR = {"shit", "shitty", "bullshit", "bitch", "bitchy", "dick",
                    "piss", "pissed", "crap", "crappy", "slut", "slutty",
                    "dick's", "pimp", "pimped", "whore", "bastard"}
        if w in _VULGAR:
            return False
        # Brand names and companies
        _BRANDS = {"directv", "citrucel", "publitech", "digitech", "hybritech",
                    "receptech", "telewest", "vegemite"}
        if w in _BRANDS:
            return False
        # Very short words: explicit allowlist
        if len(w) <= 2 and w not in {
            "be", "by", "he", "we", "me", "my", "us", "it", "is", "up",
            "i", "ye",
        }:
            return False
        # Short abbreviation artifacts
        if len(w) == 3 and w not in {
            "the", "dew", "mid", "wit", "see", "thy", "yet", "bid", "cry",
            "die", "dry", "hum", "lie", "ply", "rib", "rim", "rue",
            "shy", "sly", "spy", "tie", "try", "vie", "why", "wry",
            "dim", "dip", "dig", "bit", "big", "but", "buy", "bug",
            "cup", "cut", "due", "dug", "dye", "get", "gum", "gut",
            "hem", "her", "hew", "hid", "him", "hip", "his", "hit",
            "ice", "ire", "its", "jet", "jug", "key", "kid", "kit",
            "led", "leg", "let", "lid", "lip", "lit", "lug", "met",
            "mix", "mud", "mug", "peg", "per", "pet", "pie", "pig",
            "pit", "ply", "pub", "pug", "put", "red", "rev", "rig",
            "rip", "rub", "rug", "set", "sew", "sir", "sit", "six",
            "ski", "sky", "sly", "sub", "sum", "sup", "wig", "yew",
            "zip", "zit", "pew", "hue", "cue", "sue", "use", "dub",
            "eve", "gem", "gig", "hey", "jig", "mew", "rye", "tug",
            "wet", "web",
        }:
            return False
        # Acronyms: syllables >= 3 and length <= 4
        if word_info.syllables >= 3 and len(w) <= 4:
            return False
        return True

    def _is_common(self, word_info: WordInfo, min_freq: float = MIN_FREQ_MIDLINE) -> bool:
        """Checks if a word is common enough based on word frequency."""
        if not _WORD_FREQ:
            return True  # wordfreq not available, allow all
        freq = word_freq(word_info.word)
        return freq >= min_freq

    def _word_quality_score(self, word_info: WordInfo) -> float:
        """Returns a composite quality score for ranking word candidates."""
        score = 0.0
        w = word_info.word

        # Frequency component (0-10)
        freq = word_freq(w)
        if freq > 1e-4:
            score += 10.0
        elif freq > 1e-5:
            score += 7.0
        elif freq > 5e-6:
            score += 4.0
        elif freq > 1e-6:
            score += 2.0
        else:
            score += 0.0

        # Curated bonus (+5)
        if w in self.curated_set:
            score += 5.0

        # Penalize very short or very long words (-2)
        if len(w) <= 2 or len(w) >= 12:
            score -= 2.0

        return score

    # ------------------------------------------------------------------
    # Iambic pentameter scoring
    # ------------------------------------------------------------------
    @staticmethod
    def _iambic_score(stress: str, position: int) -> float:
        """Scores how well a word's stress pattern fits iambic meter
        at the given syllable position (0-indexed within the line).

        Ideal iambic pentameter: 0 1 0 1 0 1 0 1 0 1
        Position 0 = unstressed, 1 = stressed, etc.
        """
        if not stress:
            return 0.5  # neutral if no stress info
        score = 0.0
        for i, s in enumerate(stress):
            line_pos = position + i
            if line_pos >= 10:
                break
            # Expected: even positions unstressed (0), odd positions stressed (1)
            expected_stressed = (line_pos % 2 == 1)
            actual_stressed = (s in ("1", "2"))
            if expected_stressed == actual_stressed:
                score += 1.0
            elif s == "0" and expected_stressed:
                score -= 0.3  # unstressed where stressed expected
            elif actual_stressed and not expected_stressed:
                score -= 0.3  # stressed where unstressed expected
        return score / max(len(stress), 1)

    # ------------------------------------------------------------------
    # Word selection methods
    # ------------------------------------------------------------------
    def _pick_best_word(
        self,
        candidates: List[WordInfo],
        state: PoemState,
        is_end_word: bool = False,
    ) -> Optional[WordInfo]:
        """Ranks candidates by frequency, iambic stress, and variety."""
        if not candidates:
            return None

        # Filter: must be lyrical and not already used
        filtered = [
            c for c in candidates
            if self._is_lyrical(c)
            and c.word not in state.used_words
            and self._is_common(c, MIN_FREQ_RHYME if is_end_word else MIN_FREQ_MIDLINE)
        ]

        # Relax: lower frequency threshold but keep lyrical + unused
        if not filtered:
            filtered = [
                c for c in candidates
                if self._is_lyrical(c)
                and c.word not in state.used_words
                and self._is_common(c, MIN_FREQ_FALLBACK)
            ]

        # Relax: allow used words but keep frequency + lyrical
        if not filtered:
            filtered = [
                c for c in candidates
                if self._is_lyrical(c)
                and self._is_common(c, MIN_FREQ_FALLBACK if is_end_word else 0)
            ]

        # Last resort: just lyrical
        if not filtered:
            filtered = [c for c in candidates if self._is_lyrical(c)]
        if not filtered:
            filtered = candidates

        # Score each candidate
        position = state.current_syllables
        scored = []
        for c in filtered:
            quality = self._word_quality_score(c)
            iambic = self._iambic_score(c.stress, position) * 3.0  # weight iambic
            # End-word bonus for stressed final syllable
            stress_bonus = 1.0 if is_end_word and c.stress and c.stress[-1] in ("1", "2") else 0.0
            total = quality + iambic + stress_bonus
            scored.append((total, c))

        scored.sort(key=lambda x: -x[0])

        # Weighted random from top candidates to add variety
        top_n = min(8, len(scored))
        top = scored[:top_n]
        if not top:
            return candidates[0]

        # Weight by score (shift to positive)
        min_score = min(s for s, _ in top)
        weights = [(s - min_score + 1.0) for s, _ in top]
        total_w = sum(weights)
        r = random.random() * total_w
        cumulative = 0.0
        for i, (s, c) in enumerate(top):
            cumulative += weights[i]
            if cumulative >= r:
                return c
        return top[0][1]

    def _pick_rhyme_setter(
        self,
        budget: int,
        state: PoemState,
    ) -> Optional[WordInfo]:
        """Finds a word to establish a new rhyme family with abundant
        common rhyming partners, avoiding used rhyme sounds.
        Only considers rhyme families with at least 3 common partner words.
        """
        candidates = self.lexicon.get_candidates(syllables=budget)

        # Pre-compute which rhyme families have enough common partners
        # This is the KEY gate: we only establish rhyme sounds that can be completed
        _rhyme_partner_cache: Dict[str, int] = {}

        def family_abundance(rhyme_key: str) -> int:
            if rhyme_key in _rhyme_partner_cache:
                return _rhyme_partner_cache[rhyme_key]
            family_words = self.lexicon.get_rhyming_words(rhyme_key)
            count = len([
                w for w in family_words
                if self._is_lyrical(w)
                and self._is_common(w, MIN_FREQ_RHYME)
                and w.word not in state.used_words
            ])
            _rhyme_partner_cache[rhyme_key] = count
            return count

        # Strict filter: common, lyrical, fresh rhyme with abundant partners
        MIN_PARTNERS = 3
        valid = [
            c for c in candidates
            if self._is_lyrical(c)
            and c.word not in state.used_words
            and c.rhyme not in state.used_rhyme_sounds
            and self._is_common(c, MIN_FREQ_RHYME)
            and family_abundance(c.rhyme) >= MIN_PARTNERS
        ]

        # Relax slightly: lower partner requirement
        if not valid:
            valid = [
                c for c in candidates
                if self._is_lyrical(c)
                and c.word not in state.used_words
                and c.rhyme not in state.used_rhyme_sounds
                and self._is_common(c, MIN_FREQ_FALLBACK)
                and family_abundance(c.rhyme) >= 2
            ]

        # Last resort: any lyrical unused word
        if not valid:
            valid = [
                c for c in candidates
                if self._is_lyrical(c)
                and c.word not in state.used_words
            ]

        if not valid:
            valid = candidates

        scored = []
        for c in valid:
            abundance = family_abundance(c.rhyme)
            quality = self._word_quality_score(c)
            iambic = self._iambic_score(c.stress, state.current_syllables) * 2.0
            # Heavily weight abundance to ensure completable rhymes
            total = abundance * 3.0 + quality + iambic
            scored.append((total, c))

        scored.sort(key=lambda x: -x[0])

        top_n = min(6, len(scored))
        top = scored[:top_n]
        if not top:
            return None

        # Weighted random from top
        weights = [max(s, 0.1) for s, _ in top]
        total_w = sum(weights)
        r = random.random() * total_w
        cumulative = 0.0
        for i, (s, c) in enumerate(top):
            cumulative += weights[i]
            if cumulative >= r:
                return c
        return top[0][1]

    def _pick_flow_word(self, state: PoemState, target_syl: int) -> Optional[WordInfo]:
        """Chooses a grammatically and stylistically harmonious mid-line word."""
        last_word = (
            state.current_tokens[-1].lower().rstrip(",.;:!?")
            if state.current_tokens
            else None
        )

        # Build grammar-aware pool
        det_set = {w.word for w in self.curated_words.get("determiners", [])}
        adj_set = {w.word for w in self.curated_words.get("adjectives", [])}
        noun_set = {w.word for w in self.curated_words.get("nouns", [])}
        verb_set = {w.word for w in self.curated_words.get("verbs", [])}
        prep_set = {w.word for w in self.curated_words.get("prepositions", [])}

        if not last_word:
            # Line start: determiners, prepositions, or adjectives
            pool = (
                self.curated_words.get("determiners", [])
                + self.curated_words.get("adjectives", [])
                + self.curated_words.get("prepositions", [])
            )
        elif last_word in det_set:
            pool = (
                self.curated_words.get("adjectives", [])
                + self.curated_words.get("nouns", [])
            )
        elif last_word in adj_set:
            pool = self.curated_words.get("nouns", [])
        elif last_word in noun_set:
            pool = (
                self.curated_words.get("verbs", [])
                + self.curated_words.get("prepositions", [])
                + self.curated_words.get("conjunctions", [])
            )
        elif last_word in verb_set:
            pool = (
                self.curated_words.get("determiners", [])
                + self.curated_words.get("adverbs", [])
                + self.curated_words.get("prepositions", [])
                + self.curated_words.get("adjectives", [])
            )
        elif last_word in prep_set:
            pool = (
                self.curated_words.get("determiners", [])
                + self.curated_words.get("adjectives", [])
                + self.curated_words.get("nouns", [])
            )
        else:
            pool = (
                self.curated_words.get("adjectives", [])
                + self.curated_words.get("nouns", [])
                + self.curated_words.get("verbs", [])
                + self.curated_words.get("determiners", [])
            )

        # Filter by syllable count and avoid repetition
        matching = [
            w for w in pool
            if w.syllables == target_syl and w.word not in state.used_words
        ]
        if matching:
            return self._pick_best_word(matching, state, is_end_word=False)

        # Fallback: any curated with matching syllables
        all_curated = [
            w for cat in self.curated_words.values()
            for w in cat
            if w.syllables == target_syl and w.word not in state.used_words
        ]
        if all_curated:
            return self._pick_best_word(all_curated, state, is_end_word=False)

        # Broader fallback: any common word from lexicon
        broader = [
            w for w in self.lexicon.get_candidates(syllables=target_syl)
            if self._is_lyrical(w)
            and w.word not in state.used_words
            and self._is_common(w, MIN_FREQ_MIDLINE)
        ]
        if broader:
            return self._pick_best_word(broader, state, is_end_word=False)

        # Last resort: any word
        fallback = self.lexicon.get_candidates(syllables=target_syl)
        return self._pick_best_word(fallback, state) if fallback else None

    # ------------------------------------------------------------------
    # Turn proposal
    # ------------------------------------------------------------------
    def propose_next_word(self, state: PoemState) -> Tuple[str, str]:
        """Proposes the smartest next word for the current poem state.
        Returns: (word_with_optional_punct, reasoning)
        """
        if state.is_finished:
            return "", "Poem is already complete (14 lines)."

        budget = state.remaining_syllables
        if budget <= 0:
            return "", "Current line already reached 10 syllables."

        line_idx = state.line_index
        family = LINE_RHYME_FAMILIES[line_idx] if line_idx < 14 else "G"

        # -----------------------------------------------------------
        # Case 1: Budget is 1-2 syllables — close the line with a rhyme word
        # We restrict to 1-2 syl because that's where common rhyme words live.
        # -----------------------------------------------------------
        if budget <= 2:
            # Check if this line's rhyme family is already established
            if family in state.rhyme_sounds:
                target_rhyme = state.rhyme_sounds[family]
                candidates = self.lexicon.get_candidates(
                    syllables=budget, target_rhyme=target_rhyme
                )
                chosen = self._pick_best_word(candidates, state, is_end_word=True)
                if chosen:
                    punct = self._line_end_punctuation(line_idx)
                    state.used_words.add(chosen.word)
                    return (
                        f"{chosen.word}{punct}",
                        f"Rhyme match {family} ({target_rhyme}) [{budget} syl]",
                    )

            # Establish a new rhyme family
            best = self._pick_rhyme_setter(budget, state)
            if best:
                state.rhyme_sounds[family] = best.rhyme
                state.used_rhyme_sounds.add(best.rhyme)
                state.used_words.add(best.word)
                punct = self._line_end_punctuation(line_idx)
                return (
                    f"{best.word}{punct}",
                    f"Set rhyme {family} ({best.rhyme}) [{budget} syl]",
                )

        # -----------------------------------------------------------
        # Case 2: Mid-line word proposal (budget >= 3, or fallthrough)
        # -----------------------------------------------------------
        # Strategy: always leave 1-2 syllables for the rhyme ending word,
        # because 1-2 syllable rhyme families are most abundant with common words.
        ideal_remaining = random.choice([1, 2]) if budget > 2 else 0
        target_syl = max(1, min(budget - ideal_remaining, 3))
        # Prevent accidentally completing the line without rhyme intent
        if target_syl >= budget and budget > 1:
            target_syl = budget - 1

        word_info = self._pick_flow_word(state, target_syl)
        if not word_info:
            candidates = self.lexicon.get_candidates(syllables=target_syl)
            word_info = self._pick_best_word(candidates, state)
        if not word_info:
            word_info = self.lexicon.get_candidates(1)[0] if self.lexicon.get_candidates(1) else None

        if word_info is None:
            return "", "No candidates available"

        state.used_words.add(word_info.word)
        new_budget = budget - word_info.syllables

        if new_budget == 0:
            punct = self._line_end_punctuation(line_idx)
            return (
                f"{word_info.word}{punct}",
                f"Line completed with {word_info.syllables} syl",
            )

        return (
            word_info.word,
            f"Mid-line ({word_info.syllables} syl, {new_budget} remaining)",
        )

    # ------------------------------------------------------------------
    # Punctuation
    # ------------------------------------------------------------------
    def _line_end_punctuation(self, line_idx: int) -> str:
        """Selects appropriate Shakespearean punctuation for line ends."""
        if line_idx in (3, 7, 11, 13):
            return "."  # End of stanza / couplet
        elif line_idx in (1, 5, 9):
            return ";"  # Mid-stanza pause
        else:
            return ","

    # ------------------------------------------------------------------
    # Full sonnet generation (local simulation)
    # ------------------------------------------------------------------
    def generate_full_sonnet(self) -> str:
        """Generates a complete, flawless 14-line Shakespearean sonnet."""
        state = PoemState()
        max_iterations = 500  # safety valve
        iteration = 0

        while not state.is_finished and iteration < max_iterations:
            iteration += 1
            word, reason = self.propose_next_word(state)
            if not word:
                break

            ok, syl, rhyme, _ = self.lexicon.check_word(word)
            if not ok or syl <= 0:
                continue

            state.current_tokens.append(word)
            state.current_syllables += syl
            state.current_stress += self.lexicon.words.get(
                word.rstrip(",.;:!?").lower(), WordInfo("", 0, "", "", ())
            ).stress

            if state.current_syllables == 10:
                # Get rhyme of end word
                end_word = word.rstrip(",.;:!?").lower()
                end_info = self.lexicon.words.get(end_word)
                end_rhyme = end_info.rhyme if end_info else None
                self._close_line(state, end_rhyme)

        # Format into 4/4/4/2 stanzas
        stanzas = [
            "\n".join(state.lines[0:4]),
            "\n".join(state.lines[4:8]),
            "\n".join(state.lines[8:12]),
            "\n".join(state.lines[12:14]),
        ]
        return "\n\n".join(stanzas)
