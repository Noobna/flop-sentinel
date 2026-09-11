"""Unit tests for the Technocore Sonnet Agent Engine."""

import unittest
from pathlib import Path

from sonnet_lexicon import UPSTREAM_HASH, SonnetLexicon
from sonnet_poet import LINE_RHYME_FAMILIES, PoemState, SonnetPoet
from technocore_sonnet.sonnet_validate import read_lexicon, validate_poem, validate_word

TEST_DID = "did:key:z6MkmVhZbUKWmg3r6TTi3SVM3myYJ9BLbWYPSdc5iWPuPhb6"


class SonnetEngineTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.lexicon = SonnetLexicon(TEST_DID)
        cls.poet = SonnetPoet(cls.lexicon)
        cls.cmu_raw = read_lexicon(Path("technocore_sonnet/cmudict.dict"))

    def test_lexicon_hash_and_size(self):
        self.assertGreater(len(self.lexicon.words), 15000)
        self.assertEqual(len(self.lexicon.allowed_letters), 20)
        # Check missing letters
        missing = {"a", "f", "n", "o", "q", "x"}
        self.assertEqual(missing.intersection(self.lexicon.allowed_letters), set())

    def test_word_validation_allowed_and_rejected(self):
        # Valid poetic words
        valid_words = ["light", "bright", "time", "rhyme", "verse", "sleep", "sweet", "summer", "pure", "true"]
        for w in valid_words:
            ok, syl, rhyme, err = self.lexicon.check_word(w)
            self.assertTrue(ok, f"Expected {w} to be valid, got err: {err}")
            self.assertGreaterEqual(syl, 1)
            self.assertIsNotNone(rhyme)

        # Invalid words containing forbidden letters (a, f, n, o, q, x)
        invalid_words = ["apple", "fire", "night", "sun", "moon", "star", "flower", "queen"]
        for w in invalid_words:
            ok, syl, rhyme, err = self.lexicon.check_word(w)
            self.assertFalse(ok, f"Expected {w} to be rejected")
            self.assertIn("Letters not in DID", err)

    def test_upstream_validator_agreement(self):
        # Every word validated by our lexicon must pass the official contest validator
        sample_words = ["light", "bright", "sweet", "verse", "time", "truth", "pure", "hill", "bell", "bride"]
        for w in sample_words:
            syl_ours = self.lexicon.words[w].syllables
            syl_official = validate_word(w, TEST_DID, self.cmu_raw)
            self.assertEqual(syl_ours, syl_official, f"Syllable mismatch for {w}")

    def test_full_sonnet_generation_and_official_validation(self):
        poem = self.poet.generate_full_sonnet()
        lines = [l for l in poem.splitlines() if l.strip()]
        self.assertEqual(len(lines), 14)

        # Verify against official contest validator with exact_ten flag
        counts = validate_poem(poem, self.cmu_raw, exact_ten=True)
        self.assertEqual(counts, [10] * 14)

    def test_rhyme_scheme_structure(self):
        self.assertEqual(len(LINE_RHYME_FAMILIES), 14)
        # Check ABAB CDCD EFEF GG
        self.assertEqual(LINE_RHYME_FAMILIES[:4], ["A", "B", "A", "B"])
        self.assertEqual(LINE_RHYME_FAMILIES[4:8], ["C", "D", "C", "D"])
        self.assertEqual(LINE_RHYME_FAMILIES[8:12], ["E", "F", "E", "F"])
        self.assertEqual(LINE_RHYME_FAMILIES[12:14], ["G", "G"])

    def test_apostrophe_words_allowed(self):
        # Words with apostrophes where letters are in DID must be accepted
        apostrophe_words = ["it's", "let's", "we'll"]
        for w in apostrophe_words:
            ok, syl, rhyme, err = self.lexicon.check_word(w)
            self.assertTrue(ok, f"Expected {w} to be allowed, got: {err}")
            self.assertGreaterEqual(syl, 1)

    def test_streaming_room_word_parsing(self):
        # Space-separated stream of words from teammates, some with letters outside our DID
        stream = "shall i compare thee to a summer day thou art more lovely and more temperate"
        state = self.poet.parse_poem_text(stream)
        self.assertEqual(len(state.lines), 2)
        self.assertEqual(state.current_syllables, 0)
        self.assertEqual(state.remaining_syllables, 10)
        # Verify next word proposal does not crash or deadlock
        next_w, reason = self.poet.propose_next_word(state)
        self.assertTrue(bool(next_w))
        ok, syl, _, _ = self.lexicon.check_word(next_w)
        self.assertTrue(ok, f"Proposed word {next_w} must be in our DID vocabulary")
    def test_no_profanity_or_brands_in_sonnets(self):
        """Generated sonnets must not contain profanity or brand names."""
        banned = {"shit", "shitty", "bullshit", "bitch", "directv", "citrucel",
                  "publitech", "digitech", "hybritech", "receptech", "telewest", "vegemite"}
        for _ in range(3):
            poem = self.poet.generate_full_sonnet()
            words = {w.rstrip(",.;:!?").lower() for w in poem.split()}
            found = words & banned
            self.assertEqual(found, set(), f"Banned words found in sonnet: {found}")

    def test_end_words_are_common_english(self):
        """End-of-line rhyme words should be common English words (freq > 1e-6)."""
        try:
            from wordfreq import word_frequency
        except ImportError:
            self.skipTest("wordfreq not installed")
        poem = self.poet.generate_full_sonnet()
        lines = [l.strip() for l in poem.splitlines() if l.strip()]
        for i, line in enumerate(lines):
            words = line.split()
            end_word = words[-1].rstrip(",.;:!?").lower()
            freq = word_frequency(end_word, "en")
            self.assertGreater(
                freq, 1e-7,
                f"Line {i+1} end-word '{end_word}' has freq {freq:.2e} (too rare)"
            )

    def test_no_word_repetition_within_sonnet(self):
        """No content word should appear more than twice in a single sonnet."""
        poem = self.poet.generate_full_sonnet()
        import collections
        word_counts = collections.Counter()
        for w in poem.split():
            raw = w.rstrip(",.;:!?").lower()
            if len(raw) > 2:  # skip function words like 'the', 'by'
                word_counts[raw] += 1
        repeated = {w: c for w, c in word_counts.items() if c > 2}
        self.assertEqual(
            repeated, {},
            f"Words repeated more than twice: {repeated}"
        )


if __name__ == "__main__":
    unittest.main()
