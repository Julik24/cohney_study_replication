import os
import re
import spacy
from spacy.matcher import Matcher
from spacy.tokens import Token

#nlp = spacy.load("en_core_web_sm")

# Directory with policies txt
directory = './dataset/certs/policies/txt'

KEY_PHRASES = [
    "Compiled into binary",
    "Compiled in the binary",
    "statically stored in the code",
    "Hard Coded",
    "generated external to the module",
    "Stored in flash",
    "Static key Stored in the firmware",
    "Entered in factory",
    "in tamper protected memory",
    "With the exception of DHSK and the RNG seed, all CSPs are loaded at factory.",
    "Static N/A",
    "Embedded in FLASH",
    "Injected During Manufacture",
    "Hard-coded in the module"
]
# Compile regular expressions
KEY_PATTERNS = [re.compile(phrase.lower()) for phrase in KEY_PHRASES]

# Searches literally phrases from research; 319 results found.
# The problem point is to determine that a key phrase corresponds to X9.31 keys.
def process_text_stupid(text):
    text = text.replace('\n', ' ')
    text = text.lower()
    patterns = ['x9.31', 'cryptographic keys', 'all keys' ]
    regex = re.compile(r'\b(' + '|'.join(patterns) + r')\b')
    for idx in re.finditer(regex, text):
        for regex_pattern in KEY_PATTERNS:
            if regex_pattern.search(text[idx.start():idx.start()+200]):
                return True
    return False

# 92 results found
def process_text_straightforward(text):
    x931_mentioned = False
    hardcoded_keys_mentioned = False

    sent_lower = text.lower()
    # Check for mention of ANSI X9.31 PRNG
    for ind in re.finditer("x9.31", sent_lower):
        x931_mentioned = True
        # Check neighboring text for indications of hard-coded keys
        ran = text[max(ind.start() - 15, 0):min(ind.start() + 50, len(text))]
        if (any(word in ran for word in ["hardcoded", "predefined", "static", "constant", "fixed",
                                        "stored", "compiled", "embedded", "injected", "loaded",
                                        "hard coded", "hard-coded"])
                and not any(word in ran for word in ["internal", "not stored", "volatile", "periodically", "updated"])):
            hardcoded_keys_mentioned = True

        if hardcoded_keys_mentioned:
            break
    return x931_mentioned, hardcoded_keys_mentioned

# TODO: Replace +20 tokens context with spacy dependencies
# TODO: Add negated sentences detection
def process_text_spacy(text):
    nlp = spacy.load("en_core_web_sm")
    text = text.replace('\n', ' ')

    doc = nlp(text)

    patterns_algo = ["x9.31", "all keys", "cryptografic keys"]
    patterns_verbs = ["stored", "written", "compiled", "injected", "entered", "loaded", "embedded", "hard-coded"]
    patterns_places = ["flash", "binary", "firmware", "module", "factory"]
    patterns_nouns = ["randomseed", "seed", "key"]
    patterns_adverbs = ["statically"]

    patterns = [

        ["static"],

        ["hard", "coded"],

        ["generated", "external", "module"],

        ["tamper", "memory"],

        ["injected", "during", "manufacture"]
    ]

    found_flag = False
    for idx in range(len(doc)):
        if doc[idx].text.lower() in patterns_algo:
            context = doc[idx:idx + 60].text.lower()
            if any(part in context for part in patterns_verbs) and any(part in context for part in patterns_places):
                found_flag = True
            if any(part in context for part in patterns_nouns) and any(
                    part in context for part in patterns_verbs) and any(part in context for part in patterns_adverbs):
                found_flag = True
            for phrase in patterns:
                if all(part in context for part in phrase):
                    found_flag = True
                    break
    return found_flag


# TODO: Add different word order in patterns
# TODO: Add negation handling
def process_text_spacy_matcher(text):
    nlp = spacy.load("en_core_web_sm")

    doc = nlp(text)

    matcher = Matcher(nlp.vocab)

    patterns = [
        [{"LOWER": {
            "IN": ["stored", "written", "compiled", "injected", "entered", "loaded", "embedded", "hard-coded"]}},
         {"OP": "*"}, {"LOWER": {"IN": ["flash", "binary", "firmware", "module", "factory", "code"]}}],

        [{"LOWER": {"IN": ["randomseed", "seed", "key"]}}, {"OP": "*"}, {"LOWER": {
            "IN": ["stored", "written", "compiled", "injected", "entered", "loaded", "embedded", "hard-coded"]}},
         {"OP": "*"}, {"LOWER": {"IN": ["statically"]}}],

        [{"LOWER": {"IN": ["static"]}}, {"OP": "*"}, {"LOWER": {"IN": ["randomseed", "seed", "key"]}}],

        [{"LOWER": "hard"}, {"LOWER": "coded"}],

        [{"LOWER": "generated"}, {"OP": "*"}, {"LOWER": "external"}],

        [{"LOWER": "injected"}, {"OP": "*"}, {"LOWER": "manufacture"}],
        # [{"LOWER": "hard"}, {"LOWER": "coded"},  {"LOWER": {"IN": ["flash", "binary", "firmware", "module", "factory"]}}],
    ]

    for pattern in patterns:
        matcher.add("X931_PATTERN", [pattern])

    # bad approach because of "table" format
    """sentences = list(doc.sents)
    for idx in range(len(sentences)):
        if any(token.text.lower() == "x9.31" for token in sentences[idx]):
            for nxt_idx in range(idx, min(len(sentences), idx + 2)):
                if matcher(sentences[nxt_idx]):
                    return True
    """
    for idx in range(len(doc)):
        if doc[idx].text.lower() == "x9.31":
            context = doc[idx:idx + 20]
            if matcher(context):
                return True
    return False


"""
def process_text_spacy_randomseed(text):
    doc = nlp(text)
    x931_mentioned = False
    hardcoded_keys_mentioned = False

    # Iterate over sentences in the document
    sents = []
    for i, sent in enumerate(doc.sents):
        sents.append(sent)
    for i, sent in enumerate(sents):
        sent_lower = sent.text.lower()

        if "x9.31" in sent_lower:
            x931_mentioned = True
            # Check neighboring sentences for indications of hard-coded keys
            for neighbor_sent in sents[i - 1:i + 2]:
                neighbor_sent_lower = neighbor_sent.text.lower()
            if (any(word in neighbor_sent_lower for word in ["seed", "seeding", "seeded"])
                    and any(word in neighbor_sent_lower for word in ["hardcoded", "predefined", "static", "constant", "fixed",
                                "stored", "compiled", "embedded", "injected", "loaded",
                                "hard coded", "hard-coded"])):
                hardcoded_keys_mentioned = True
            if hardcoded_keys_mentioned:
                break
    return x931_mentioned, hardcoded_keys_mentioned"""