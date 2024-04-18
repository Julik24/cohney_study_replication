import re
import os
from sec_certs.dataset.fips import FIPSDataset

# Directory with privacy policies txt
DIRECTORY = './dataset/certs/policies/txt'

# Key phrases indicating vulnerable products mentioned in research
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

# Checks if a given text contains one of key phrases
def check_keywords(text):
    # To deal with table data
    text = text.replace('\n', ' ')
    text = text.lower()
    hardcoded_keys_mentioned = False

    for regex_pattern in KEY_PATTERNS:
        if regex_pattern.search(text):
            hardcoded_keys_mentioned = True
            break
    return hardcoded_keys_mentioned


# Returns a list of vulnerable products from the research, which we will consider a reference;
# 34 of 40 products found; without key phrases(only by vendor and product name) check founds 50 products
def get_vulnerable_products_from_research(dset: FIPSDataset):
    potentially_vulnerable_products = []
    vulnerable_products = []
    for cert in dset:
        if ("BeCrypt" in cert.manufacturer and "Cryptographic Library" in cert.web_data.module_name)\
            or ("Cisco" in cert.manufacturer and "Aironet" in cert.web_data.module_name)\
            or ("DeltaCrypt" in cert.manufacturer and "FIPS Module" in cert.web_data.module_name)\
            or ("Fortinet" in cert.manufacturer and "FortiOS" in cert.web_data.module_name and "4" in cert.web_data.module_name)\
            or ("MRV" in cert.manufacturer and "LX" in cert.web_data.module_name)\
            or ("Neoscale" in cert.manufacturer and "CryptoStor" in cert.web_data.module_name)\
            or ("Neopost" in cert.manufacturer and "Postal Security" in cert.web_data.module_name)\
            or ("Renesas" in cert.manufacturer and "AE57C1" in cert.web_data.module_name)\
            or ("TechGuard" in cert.manufacturer and "PoliWall" in cert.web_data.module_name)\
            or ("Tendyron" in cert.manufacturer and "OnKey193" in cert.web_data.module_name)\
            or ("ViaSat" in cert.manufacturer and "FlagStone" in cert.web_data.module_name)\
            or ("Vocera" in cert.manufacturer and "Cryptographic Module" in cert.web_data.module_name):
            potentially_vulnerable_products.append(cert)

    for cert in potentially_vulnerable_products:
        policy_path = os.path.join(DIRECTORY, cert.dgst + ".txt")
        with open(policy_path, 'r') as file:
            content = file.read()
            if check_keywords(content):
                vulnerable_products.append(cert.dgst)
    return vulnerable_products

# Returns set of X9.31 versions, used by reference vulnerable products
def get_x931_algorithms_from_research(dset):
    x931_versions = set()
    vulnerable_products_dgsts = get_vulnerable_products_from_research(dset)
    for dgst in vulnerable_products_dgsts:
        for algo in dset[dgst].heuristics.algorithms:
            if "RNG" in algo:
                x931_versions.add(algo)
    return x931_versions
