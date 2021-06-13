#!/usr/bin/env python3

################################################################################################
#
# GlacierScript:  Part of the Glacier Protocol (http://glacierprotocol.org)
#
# GlacierScript is designed specifically for use in the context of executing the broader Glacier
# Protocol, a step-by-step procedure for high-security cold storage of Bitcoin.  It is not
# intended to be used as standalone software.
#
# GlacierScript primarily replaces tasks that users would otherwise be doing manually, such as
# typing things on the command line, copying-and-pasting strings, and hand-editing JSON.  It
# mostly consists of print statements, user input, string & JSON manipulation, and command-line
# wrappers around Bitcoin Core and other applications (e.g. those involved in reading and writing
# QR codes.)
#
# GlacierScript avoids cryptographic and other security-sensitive operations as much as possible.
#
# GlacierScript depends on the following command-line applications:
# - Bitcoin Core (http://bitcoincore.org)
# - qrencode (QR code writer: http://packages.ubuntu.com/xenial/qrencode)
# - zbarimg (QR code reader: http://packages.ubuntu.com/xenial/zbar-tools)
#
################################################################################################

# standard Python libraries
import argparse
import json
import os
import shlex
import subprocess
import sys
import time
import re
import glob
from decimal import Decimal
from hashlib import sha256, md5, new as hashlib_new
from binascii import unhexlify, hexlify
from mnemonic import Mnemonic

# Taken from https://github.com/keis/base58
from base58 import b58encode_check, b58decode

SATOSHI_PLACES = Decimal("0.00000001")

verbose_mode = 0

FEE_RATE_MULTIPLIER = 10**5 # BTC/kB -> sat/byte

LINE_BREAK = "=" * 80

FINGERPRINT_PATTERN = "(?P<fng>[a-fA-F0-9]{8})"
PATH_PATTERN = "(?P<path>(?:(?:/)(?:\d+)(?:['h]{0,1}))*)"
XPUB_PATTERN = "(?P<xpub>\w{110,112})"
DESCRIPTOR_KEY_PATTERN = re.compile("^\[" + FINGERPRINT_PATTERN + PATH_PATTERN + "\]" + XPUB_PATTERN + "$")
UNHARDENED_PATH_PATTERN = "^/([01])/(0|[1-9][0-9]*)$" # match /{change}/{idx} and prevent leading zeros
################################################################################################
#
# Minor helper functions
#
################################################################################################

def hash_sha256(s):
    """A thin wrapper around the hashlib SHA256 library to provide a more functional interface"""
    m = sha256()
    m.update(s.encode('ascii'))
    return m.hexdigest()


def hash_md5(s):
    """A thin wrapper around the hashlib md5 library to provide a more functional interface"""
    m = md5()
    m.update(s.encode('ascii'))
    return m.hexdigest()

def hash160(string):
    """A thin wrapper around hashlib to compute the hash160 (SHA256 followed by RIPEMD160)"""
    intermed = sha256(string).digest()
    return hashlib_new('ripemd160', intermed).digest()

################################################################################################
#
# Subprocess helper functions
#
################################################################################################

def verbose(content):
    if verbose_mode: print(content)


def run_subprocess(exe, *args):
    """
    Run a subprocess (bitcoind or bitcoin-cli)
    Returns => (command, return code, output)

    exe: executable file name (e.g. bitcoin-cli)
    args: arguments to exe
    """
    cmd_list = [exe] + cli_args + list(args)
    verbose("bitcoin cli call:\n  {0}\n".format(" ".join(shlex.quote(x) for x in cmd_list)))
    with subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as pipe:
        output, _ = pipe.communicate()
    output = output.decode('ascii')
    retcode = pipe.returncode
    verbose("bitcoin cli call return code: {0}  output:\n  {1}\n".format(retcode, output))
    return (cmd_list, retcode, output)


def bitcoin_cli_call(*args):
    """
    Run `bitcoin-cli`, return OS return code
    """
    _, retcode, _ = run_subprocess("bitcoin-cli", *args)
    return retcode


def bitcoin_cli_checkoutput(*args):
    """
    Run `bitcoin-cli`, fail if OS return code nonzero, return output
    """
    cmd_list, retcode, output = run_subprocess("bitcoin-cli", *args)
    if retcode != 0: raise subprocess.CalledProcessError(retcode, cmd_list, output=output)
    return output


def bitcoin_cli_json(*args):
    """
    Run `bitcoin-cli`, parse output as JSON
    """
    return json.loads(bitcoin_cli_checkoutput(*args))


def bitcoind_call(*args):
    """
    Run `bitcoind`, return OS return code
    """
    _, retcode, _ = run_subprocess("bitcoind", *args)
    return retcode


################################################################################################
#
# Read & validate random data from the user
#
################################################################################################

def validate_rng_seed(seed, min_length):
    """
    Validates random hexadecimal seed
    returns => <boolean>

    seed: <string> hex string to be validated
    min_length: <int> number of characters required.  > 0
    """

    if len(seed) < min_length:
        print("Error: Computer entropy must be at least {0} characters long.".format(min_length))
        return False

    if len(seed) % 2 != 0:
        print("Error: Computer entropy must contain an even number of characters.")
        return False

    try:
        int(seed, 16)
    except ValueError:
        print("Error: Illegal character. Computer entropy must be composed of hexadecimal characters only (0-9, a-f).")
        return False

    return True


def read_rng_seed_interactive(min_length):
    """
    Reads random seed (of at least min_length hexadecimal characters) from standard input
    returns => string

    min_length: <int> minimum number of bytes in the seed.
    """

    char_length = min_length * 2

    def ask_for_rng_seed(length):
        print("Enter at least {0} characters of computer entropy. Spaces are OK, and will be ignored:".format(length))

    ask_for_rng_seed(char_length)
    seed = input()
    seed = unchunk(seed)

    while not validate_rng_seed(seed, char_length):
        ask_for_rng_seed(char_length)
        seed = input()
        seed = unchunk(seed)

    return seed


def validate_dice_seed(dice, min_length):
    """
    Validates dice data (i.e. ensures all digits are between 1 and 6).
    returns => <boolean>

    dice: <string> representing list of dice rolls (e.g. "5261435236...")
    """

    if len(dice) < min_length:
        print("Error: You must provide at least {0} dice rolls.".format(min_length))
        return False

    for die in dice:
        try:
            i = int(die)
            if i < 1 or i > 6:
                print("Error: Dice rolls must be between 1 and 6.")
                return False
        except ValueError:
            print("Error: Dice rolls must be numbers between 1 and 6.")
            return False

    return True


def read_dice_seed_interactive(min_length):
    """
    Reads min_length dice rolls from standard input, as a string of consecutive integers
    Returns a string representing the dice rolls
    returns => <string>

    min_length: <int> number of dice rolls required.  > 0.
    """

    def ask_for_dice_seed(x):
        print("Enter {0} dice rolls (example: 62543 16325 21341...) Spaces are OK, and will be ignored:".format(x))

    ask_for_dice_seed(min_length)
    dice = input()
    dice = unchunk(dice)

    while not validate_dice_seed(dice, min_length):
        ask_for_dice_seed(min_length)
        dice = input()
        dice = unchunk(dice)

    return dice


################################################################################################
#
# private key generation
#
################################################################################################

def xor_hex_strings(str1, str2):
    """
    Return xor of two hex strings.
    An XOR of two pieces of data will be as random as the input with the most randomness.
    We can thus combine two entropy sources in this way as a safeguard against one source being
    compromised in some way.
    For details, see http://crypto.stackexchange.com/a/17660

    returns => <string> in hex format
    """
    if len(str1) != len(str2):
        raise Exception("tried to xor strings of unequal length")
    str1_dec = int(str1, 16)
    str2_dec = int(str2, 16)

    xored = str1_dec ^ str2_dec

    return "{:0{}x}".format(xored, len(str1))

################################################################################################
#
# Bitcoin helper functions
#
################################################################################################

def ensure_bitcoind_running():
    """
    Start bitcoind (if it's not already running) and ensure it's functioning properly
    """
    # start bitcoind.  If another bitcoind process is already running, this will just print an error
    # message (to /dev/null) and exit.
    #
    # -connect=0.0.0.0 because we're doing local operations only (and have no network connection anyway)
    bitcoind_call("-daemon", "-connect=0.0.0.0")

    # verify bitcoind started up and is functioning correctly
    times = 0
    while times <= 20:
        times += 1
        if bitcoin_cli_call("getnetworkinfo") == 0:
            create_default_wallet()
            return
        time.sleep(0.5)

    raise Exception("Timeout while starting bitcoin server")


def create_default_wallet():
    """
    Ensure the default wallet exists and is loaded.
    Since v0.21, Bitcoin Core will not create a default wallet when
    started for the first time.
    """
    loaded_wallets = bitcoin_cli_json("listwallets")
    if "" in loaded_wallets:
        return  # default wallet already loaded
    all_wallets = bitcoin_cli_json("listwalletdir")
    # {
    #     "wallets": [
    #         {
    #             "name": ""
    #         }
    #     ]
    # }
    found = any(w["name"] == "" for w in all_wallets["wallets"])
    cmd = "loadwallet" if found else "createwallet"
    loaded_wallet = bitcoin_cli_json(cmd, "")
    if loaded_wallet["warning"]:
        raise Exception("problem running {} on default wallet".format(cmd))  # pragma: no cover

def require_minimum_bitcoind_version(min_version):
    """
    Fail if the bitcoind version in use is older than required
    <min_version> - required minimum version in format of getnetworkinfo, i.e. 150100 for v0.15.1
    """
    networkinfo = bitcoin_cli_json("getnetworkinfo")

    if int(networkinfo["version"]) < min_version:
        print("ERROR: Your bitcoind version is too old. You have {}, I need {} or newer. Exiting...".format(networkinfo["version"], min_version))
        sys.exit()

def get_xpub_from_xkey(xkey):
    """
    Returns the xpub for a given xkey

    xkey: <string> base58 encoded extended key
    """
    descriptor = "pk({})".format(xkey)
    out = bitcoin_cli_json("getdescriptorinfo", descriptor)
    public_descriptor = out['descriptor'] # example: 'pk(XPUB)#checksum'
    return public_descriptor[3:-10] # slice off 'pk(' prefix and ')#checksum' suffix

def bip32_deserialize(data):
    """
    Deserialize a string into a BIP32 extended key (assumes string is valid)

    See the bip32 implementation to validate correctness:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format

    Parameters:
        data (str): a serialized bip32 exteneded key
    """
    PRIVATE = [b'\x04\x88\xAD\xE4', b'\x04\x35\x83\x94'] # mainnet and testnet private version bits
    dbin = b58decode(data)
    vbytes = dbin[0:4]
    depth = dbin[4]
    fingerprint = dbin[5:9]
    i = dbin[9:13]
    chaincode = dbin[13:45]
    key = dbin[46:78] + b'\x01' if vbytes in PRIVATE else dbin[45:78]
    return (vbytes, depth, fingerprint, i, chaincode, key)

def get_fingerprint_from_xkey(xkey):
    """
    Returns the BIP32 fingerprint for the given extended key

    xkey: <string> valid bip32 extended key
    """
    xpub = get_xpub_from_xkey(xkey)
    vbytes, depth, fingerprint, i, chaincode, key = bip32_deserialize(xpub)
    fp_bytes = hash160(key)[:4]
    return hexlify(fp_bytes).decode('ascii')

def is_valid_xpub(xpub):
    """
    Returns whether the string is a valid xpub

    xpub    (str): potential xpub
    """
    try:
        descriptor = "pk({})".format(xpub)
        # validate that the input string is an xpub
        bitcoin_cli_checkoutput("getdescriptorinfo", descriptor)
        return True
    except subprocess.CalledProcessError:
        print("Error: The provided xpub is invalid. Exiting.")
    sys.exit(1)

def parse_descriptor_key(key):
    regex_match = re.match(DESCRIPTOR_KEY_PATTERN, key)
    if regex_match is None:
        print("Error: The provided descriptor key is invalid. Exiting.")
        sys.exit(1)
    fng, path, xpub = regex_match.group('fng'), regex_match.group('path'), regex_match.group('xpub')
    # parse path
    if path == "":
        path = "m"
    else:
        path_arr = path.replace("h", "'").split("/")[1:]
        for idx in path_arr:
            if idx[-1] == "'":
                idx = idx[:-1]
            if str(int(idx)) != idx: # check for leading zeros
                print("Error: The provided descriptor key contains leading zeros. Exiting.")
                sys.exit(1)
        path = "m/" + "/".join(path_arr)
    # validate xpub
    is_valid_xpub(xpub)
    return fng, path, xpub

def parse_mnemonic_to_master_key(string):
    mnemo = Mnemonic("english")
    words = string.split()
    mnemonic = " ".join(words)
    if len(words) not in {12, 24}:
        print("Error: Mnemonic phrase must be either 12 or 24 words long. Exiting.")
        sys.exit(1)
    if mnemo.check(mnemonic) != True:
        print("Error: The mnemonic phrase is invalid. Exiting.")
        sys.exit(1)
    seed = mnemo.to_seed(mnemonic)
    return mnemo.to_hd_master_key(seed, network in {"testnet", "regtest"})

def get_mnemonic_interactive():
    """
    Prompts the user for a valid (12 or 24 word) BIP39 mnemonic phrase
    return => <string> xprv derived from the mnemonic (and empty passphrase)
    """
    string = input("\nEnter your BIP39 mnemonic phrase (separate the words with whitespace): ")
    return parse_mnemonic_to_master_key(string)

def get_descriptor_keys_interactive(n):
    """
    Prompts the user for n unique and valid descriptor keys (must include fingerprint)

    n: <int> the number of descriptor keys to import

    returns: List<string> the list of validated descriptor keys
    """
    keys = []
    print("\nInput {} valid descriptor keys".format(n))
    for idx in range(n):
        key_str = input("\nEnter descriptor key #{}: ".format(idx+1))
        key = parse_descriptor_key(key_str)
        keys.append(key)

    unique_fingerprints = set(map(lambda key: key[0], keys))
    unique_xpubs = set(map(lambda key: key[2], keys))
    if len(unique_fingerprints) != n or len(unique_xpubs) != n:
        print("Expected {} unique descriptor keys. Exiting".format(n))
        sys.exit(1)

    return keys

def wsh_descriptor(dkeys, m, change = 0):
    """
    Creates the desired Bitcoin Core sortedmulti wsh descriptor for
    the provided descriptor keys

    dkeys: List<string> wallet descriptor keys
    m: <int> number of multisig keys required for withdrawal
    change: <int> internal or external descriptor
    """

    # create descriptor without checksum
    dkeys_str = ",".join([
        "[{}{}]{}/{}/*".format(fng, path[1:], dkey, str(change))
        for fng, path, dkey
        in dkeys
    ])
    descriptor = "wsh(sortedmulti({},{}))".format(str(m), dkeys_str)

    # getdescriptorinfo and append checksum
    output = bitcoin_cli_json("getdescriptorinfo", descriptor)
    return descriptor + "#" + output["checksum"]

def importmulti(idxs, dkeys, m):
    """
    Imports private key data for (external and internal) addresses at the given
    indices into Bitcoin Core

    idxs: Set<int> address indices to perform the import
    dkeys: List<string> wallet descriptor keys
    m: <int> number of multisig keys required for withdrawal
    """
    for change in {0, 1}:
        desc = wsh_descriptor(dkeys, m, change)
        args = []
        for i in idxs:
            args.append({
                "desc": desc,
                "internal": True if change == 1 else False,
                "range": [i, i],
                "timestamp": "now",
                "keypool": False,
                "watchonly": False
            })
        bitcoin_cli_json("importmulti", json.dumps(args))

def deriveaddresses(dkeys, m, start, end, change=0):
    """
    Derives wallet addresses based on the requested parameters

    dkeys: List<string> wallet descriptor keys
    m: <int> number of multisig keys required for withdrawal
    start: <int> first index to derive address of
    end: <int> last index to derive address of
    change: <int> internal or external address
    """
    desc = wsh_descriptor(dkeys, m, change)
    return bitcoin_cli_json("deriveaddresses", desc, json.dumps([start, end]))


def walletprocesspsbt(psbt, idxs, dkeys, m):
    """
    Signs a psbt after importing the necessary key data

    psbt: <str> base64 encoded psbt
    idxs: Set<int> indices to import into Bitcoin Core to sign the psbt
    dkeys: List<string> wallet descriptor keys (includes 1 xprv)
    m: <int> number of multisig keys required for withdrawal
    """

    # import the descriptors necessary to process the provided psbt
    importmulti(idxs, dkeys, m)
    return bitcoin_cli_json("walletprocesspsbt", psbt, "true", "ALL")

def validate_psbt_bip32_derivs(dkeys, psbt_in_or_out, i, what):
    # Ensure input contains BIP32 derivations
    if "bip32_derivs" not in psbt_in_or_out:
        return ("Tx {} {} is missing bip32 metadata.".format(what, i), None, None)
    bip32_derivs = psbt_in_or_out["bip32_derivs"]

    # Ensure the bip32 derivations specified in the psbt input/output are consistent with out wallet's
    expected_fps = set(map(lambda dkey: dkey[0], dkeys))
    actual_fps = set(map(lambda bip32_deriv: bip32_deriv["master_fingerprint"], bip32_derivs))
    if expected_fps != actual_fps or len(dkeys) != len(bip32_derivs):
        return ("Tx {} {} has the wrong set of fingerprints.".format(what, i), None, None)

    # Ensure each public key derives from the correct hardened path for its master fingerprint, and
    # the _same_, _allowed_ unhardened path
    input_paths = set()
    for fng, expected_path, xpub in dkeys:
        # get corresponding bip32 derivation by master fingerprint (guaranteed to succeed)
        bip32_deriv = list(filter(lambda bip32_deriv: bip32_deriv["master_fingerprint"] == fng, bip32_derivs)).pop()
        # check that hardened path matches cosigner hardened derivation path
        path_arr = bip32_deriv["path"].split(expected_path)
        if len(path_arr) != 2 and path_arr[0] != "":
            return ("Tx {} {} contains an invalid hardened derivation path for cosigner {}.".format(what, i, fng), None, None)
        input_paths.add(path_arr[1])
    if len(input_paths) != 1:
        return ("Tx {} {} contains different unhardened derivation paths.".format(what, i), None, None)
    input_path = input_paths.pop()
    match_object = re.match(UNHARDENED_PATH_PATTERN, input_path)
    if match_object is None:
        return ("Tx {} {} contains an unsupported derivation path: '..{}'.".format(what, i, input_path), None, None)
    change, idx = map(int, match_object.groups())
    return (None, change, idx)

def validate_psbt_in(dkeys, m, _input, i, response):
    # Ensure input spends a witness UTXO
    if not ("non_witness_utxo" in _input and "witness_utxo" in _input):
        return "Tx input {} must include both PSBT_IN_WITNESS_UTXO and PSBT_IN_NON_WITNESS_UTXO fields.".format(i)

    # Ensure the witness utxo is the expected type: witness_v0_scripthash
    scriptpubkey_type = _input["witness_utxo"]["scriptPubKey"]["type"]
    if scriptpubkey_type != "witness_v0_scripthash":
        return "Tx input {} contains an incorrect scriptPubKey type.".format(i)

    # Ensure input contains a witness script
    if "witness_script" not in _input:
        return "Tx input {} must include a PSBT_IN_WITNESS_SCRIPT field.".format(i)

    # Ensure that the witness script hash equals the scriptPubKey
    witness_script = _input["witness_script"]["hex"]
    witness_script_hash = hexlify(sha256(unhexlify(witness_script)).digest()).decode()
    scriptPubKeyParts = _input["witness_utxo"]["scriptPubKey"]["asm"].split(" ")
    if witness_script_hash != scriptPubKeyParts[1]:
        return "The SHA256 of PSBT_IN_WITNESS_SCRIPT and PSBT_IN_WITNESS_UTXO don't match for Tx input {}.".format(i)

    # Validate psbt input bip32 derivations
    (bip32_derivs_err, change, idx) = validate_psbt_bip32_derivs(dkeys, _input, i, "input")
    if bip32_derivs_err is not None:
        return bip32_derivs_err

    # Ensure that the actual address contained in the witness_utxo matches our
    # expectations given the BIP32 derivations provided
    actual_address = _input["witness_utxo"]["scriptPubKey"]["address"]

    # Ensure expected address implied by metadata matches actual address supplied
    [expected_address] = deriveaddresses(dkeys, m, idx, idx, change)
    if expected_address != actual_address:
        return "Tx input {} contains an incorrect address based on the provided bip32 metadata.".format(i)

    # Ensure sighash is not set at all or set correctly
    if "sighash" in _input and _input["sighash"] != "ALL":
        return "Tx input {} contains an unsupported PSBT_IN_SIGHASH_TYPE type: {}".format(i, _input["sighash"])

    # validation successful (update importmulti indices)
    response["importmulti_idxs"].add(idx)
    return None

def validate_psbt_out(dkeys, m, tx, output, i, response):
    # Get the corresponding Tx ouput
    tx_out = tx["vout"][i]

    # The output can't be change if it doesn't spend back to the `witness_v0_scripthash` script type
    scriptpubkey_type = tx_out["scriptPubKey"]["type"]
    if scriptpubkey_type != "witness_v0_scripthash":
        return None

    # The output can't be change if it doesn't contain bip32 metadata
    if "bip32_derivs" not in output:
        return None

    # Get the actual Tx address from the scriptPubKey
    [actual_address] = tx_out["scriptPubKey"]["addresses"]

    # Validate psbt output bip32 derivations
    (bip32_derivs_err, change, idx) = validate_psbt_bip32_derivs(dkeys, output, i, "output")
    if bip32_derivs_err is not None:
        return bip32_derivs_err

    # Ensure the actual address in the Tx output matches the expected address given
    # the BIP32 derivation paths
    [expected_address] = deriveaddresses(dkeys, m, idx, idx, change)
    if expected_address != actual_address:
        return "Tx output {} spends bitcoin to an incorrect address based on the provided bip32 metadata.".format(i)

    # Ensure that the witness script hash maps to the transaction output's scriptPubKey
    if "witness_script" not in output:
        return "Tx output {} must include a PSBT_OUT_WITNESS_SCRIPT field.".format(i)
    witness_script = output["witness_script"]["hex"]
    witness_script_hash = hexlify(sha256(unhexlify(witness_script)).digest()).decode()
    scriptPubKeyParts = tx_out["scriptPubKey"]["asm"].split(" ")
    if witness_script_hash != scriptPubKeyParts[1]:
        return "The SHA256 of PSBT_OUT_WITNESS_SCRIPT and the scriptPubKey of Tx output {} don't match.".format(i)

    response["change_idxs"].append(i) # change validations pass
    return None

def validate_psbt(psbt_raw, dkeys, m):
    """
    ******************************************************************
    ********************  SECURITY CRITICAL  *************************
    ******************************************************************
    Validate whether the psbt is safe to sign based on exhaustive checks


    psbt_raw: <string>  base64 encoded psbt
    dkeys: List<string> wallet descriptor keys (including our xprv)
    m: <int> number of multisig keys required for withdrawal

    returns: dict
        error:            <str> an error if one is found
        warning:          List<str> warnings about psbt
        psbt:             <dict> python dict loaded from decodepsbt RPC call
        change_idxs:      List<int> list of change indices
        importmulti_idxs: Set<int> set of indices to pass to the importmulti RPC call
        analysis:         <dict> python dict loaded from analyzepsbt RPC call
    """
    response = {
        "error": None,
        "warning": [],
        "psbt": None,
        "change_idxs": [],
        "importmulti_idxs": set(),
        "analysis": None
    }
    try:
        # attempt to decode psbt
        psbt = bitcoin_cli_json("decodepsbt", psbt_raw)
        # attempt to analyze psbt (should always succeed if decode succeeds)
        response["analysis"] = bitcoin_cli_json("analyzepsbt", psbt_raw)

        # validate all inputs
        for i, _input in enumerate(psbt["inputs"]):
            psbt_in_validation_err = validate_psbt_in(dkeys, m, _input, i, response)
            if psbt_in_validation_err is not None:
                response["error"] = psbt_in_validation_err
                return response

        # validate all outputs
        tx = psbt["tx"]
        for i, output in enumerate(psbt["outputs"]):
            psbt_out_validation_err = validate_psbt_out(dkeys, m, tx, output, i, response)
            if psbt_out_validation_err is not None:
                response["error"] = psbt_out_validation_err
                return response

        # Display a warning to the user if we can't recognize any change (suspicious)
        if len(response["change_idxs"]) == 0:
            no_change_warning = "No change outputs were identified in this transaction. "
            no_change_warning += "If you intended to send bitcoin back to your wallet as change, "
            no_change_warning += "abort this signing process. Otherwise, you can safely ignore this warning."
            response["warning"].append(no_change_warning)

        # Validations succeded!
        response["psbt"] = psbt

    # Catches exceptions in decoding or analyzing PSBT
    except subprocess.CalledProcessError:
        response["error"] = "The provided base64 encoded input is NOT a valid PSBT"
    # Catch any other unexpected exception that may occur
    except:
        response["error"] = "An unexpected error occurred during the PSBT validation process"
    return response

################################################################################################
#
# QR code helper functions
#
################################################################################################

def decode_one_qr(filename):
    """
    Decode a QR code from an image file, and return the decoded string.
    """
    zresults = subprocess.run(["zbarimg", "--set", "*.enable=0", "--set", "qr.enable=1",
                              "--quiet", "--raw", filename], check=True, stdout=subprocess.PIPE)
    return zresults.stdout.decode('ascii').strip()


def decode_qr(filenames):
    """
    Decode a (series of) QR codes from a (series of) image file(s), and return the decoded string.
    """
    return ''.join(decode_one_qr(f) for f in filenames)


def write_qr_code(filename, data):
    """
    Write one QR code.
    """
    subprocess.run(["qrencode", "-o", filename, data], check=True)


def write_and_verify_qr_code(name, filename, data):
    """
    Write a QR code and then read it back to try and detect any tricksy malware tampering with it.

    name: <string> short description of the data
    filename: <string> filename for storing the QR code
    data: <string> the data to be encoded

    If data fits in a single QR code, we use filename directly. Otherwise
    we add "-%02d" to each filename; e.g. transaction-01.png transaction-02.png.

    The `qrencode` program can do this directly using "structured symbols" with
    its -S option, but `zbarimg` doesn't recognize those at all. See:
    https://github.com/mchehab/zbar/issues/66

    It's also possible that some mobile phone QR scanners won't recognize such
    codes. So we split it up manually here.

    The theoretical limit of alphanumeric QR codes is 4296 bytes, though
    somehow qrencode can do up to 4302.

    """
    # Remove any stale files, so we don't confuse user if a previous
    # withdrawal created 3 files (or 1 file) and this one only has 2
    base, ext = os.path.splitext(filename)
    for deleteme in glob.glob("{}*{}".format(base, ext)):
        os.remove(deleteme)
    MAX_QR_LEN = 3000
    if len(data) <= MAX_QR_LEN:
        write_qr_code(filename, data)
        filenames = [filename]
    else:
        idx = 1
        filenames = []
        intdata = data
        while len(intdata) > 0:
            thisdata = intdata[0:MAX_QR_LEN]
            intdata = intdata[MAX_QR_LEN:]
            thisfile = "{}-{:02d}{}".format(base, idx, ext)
            filenames.append(thisfile)
            write_qr_code(thisfile, thisdata)
            idx += 1

    qrdata = decode_qr(filenames)
    if qrdata != data:
        print("********************************************************************")
        print("WARNING: {} QR code could not be verified properly. This could be a sign of a security breach.".format(name))
        print("********************************************************************")

    print("QR code for {0} written to {1}".format(name, ','.join(filenames)))

################################################################################################
#
# User sanity checking
#
################################################################################################

def safety_checklist():

    checks = [
        "Are you running this on a computer WITHOUT a network connection of any kind?",
        "Have the wireless cards in this computer been physically removed?",
        "Are you running on battery power?",
        "Are you running on an operating system booted from a USB drive?",
        "Is your screen hidden from view of windows, cameras, and other people?",
        "Are smartphones and all other nearby devices turned off and in a Faraday bag?"]

    for check in checks:
        answer = input(check + " (y/n)?")
        if answer.upper() != "Y":
            print("\nError: Safety check failed. Exiting.")
            sys.exit(1)


################################################################################################
#
# Main "entropy" function
#
################################################################################################


def unchunk(string):
    """
    Remove spaces in string
    """
    return string.replace(" ", "")


def chunk_string(string, length):
    """
    Splits a string into chunks of [length] characters, for easy human readability
    Source: https://stackoverflow.com/a/18854817/11031317
    """
    return (string[0+i:length+i] for i in range(0, len(string), length))


def entropy(length):
    """
    Generate 1 random string for the user from /dev/random
    """
    safety_checklist()

    print("\nMaking a random data string....")
    print("(If the string doesn't appear right away, please continually move your mouse cursor. These movements generate entropy which is used to create random data.)\n")

    seed = subprocess.check_output("xxd -l {} -p /dev/random".format(length), shell=True)
    seed = seed.decode('ascii').replace('\n', '')
    print("Computer entropy: {}".format(" ".join(chunk_string(seed, 4))))


################################################################################################
#
# main "create wallet" function
#
################################################################################################
def create_wallet_interactive(dice_seed_length=100, rng_seed_length=32, data_length=32):
    """
    Generate data for a new cold storage multisignature signatory (mnemonic phrase, xpub)
    dice_seed_length: <int> minimum number of dice rolls required
    rng_seed_length: <int> minimum length of random seed required
    data_length: <int> number of bytes used to construct mnemonic (32 => 24 words, 16 => 12 words)
    """
    safety_checklist()
    ensure_bitcoind_running()
    require_minimum_bitcoind_version(200100)

    print("\nCreating cold storage private key data.\n")

    dice_seed_string = read_dice_seed_interactive(dice_seed_length)
    dice_seed_hash = hash_sha256(dice_seed_string)

    rng_seed_string = read_rng_seed_interactive(rng_seed_length)
    rng_seed_hash = hash_sha256(rng_seed_string)

    # back to hex string
    hex_private_key = xor_hex_strings(dice_seed_hash, rng_seed_hash)
    bin_private_key = unhexlify(hex_private_key)[:data_length]

   # convert private key to BIP39 mnemonic phrase
    mnemo = Mnemonic("english")
    mnemonic = mnemo.to_mnemonic(bin_private_key)
    seed = mnemo.to_seed(mnemonic)
    xprv = mnemo.to_hd_master_key(seed, network in {"testnet", "regtest"})

    print("\nBIP39 Mnemonic Phrase: ")
    words = mnemonic.split(" ")
    for i, word in enumerate(words):
        print("{}. {}".format(i + 1, word))

    xpub = get_xpub_from_xkey(xprv)
    fng = get_fingerprint_from_xkey(xpub)
    key_origin = "[{}]{}".format(fng, xpub)
    print("\npublic key metadata:\n{}\n".format(key_origin))

    write_and_verify_qr_code("public-key-metadata", "public-key-metadata.png", key_origin)

################################################################################################
#
# main "deposit" function
#
################################################################################################

def view_addresses_interactive(m, n, my_xprv = None, trust_xpubs = False):
    """
    Show the addresses for a multisignature wallet with the user-provided policy
    m: <int> number of multisig keys required for withdrawal
    n: <int> total number of multisig keys
    trust_xpubs: <boolean> only use xpubs to generate addresses
    """

    safety_checklist()
    ensure_bitcoind_running()
    require_minimum_bitcoind_version(200100)

    if trust_xpubs:
        # only prompt user for xpubs
        dkeys = get_descriptor_keys_interactive(n)
        xkeys = list(map(lambda dkey: dkey[2], dkeys))
    else:
        # prompt user for mnemonic and all xpubs in the multisignature quorum
        if my_xprv is None:
            my_xprv = get_mnemonic_interactive()
        my_xpub = get_xpub_from_xkey(my_xprv)
        dkeys = get_descriptor_keys_interactive(n)
        xpubs = list(map(lambda dkey: dkey[2], dkeys))

        if my_xpub not in xpubs:
            print("Error: No xpubs match the xpub of the provided mnemonic phrase. Exiting.")
            sys.exit(1)
        xkeys = [xpub if xpub != my_xpub else my_xprv for xpub in xpubs]

    # first address index to show, change flag, number of addresses to show
    start, change, N = 0, 0, 10
    while True:
        print(LINE_BREAK)
        addresses = deriveaddresses(dkeys, m, start, start + N - 1, change)
        print("Derivation Path, Address")
        for i, addr in enumerate(addresses):
            idx = start + i
            print("../{}/{}, {} (Enter {} to save as a QR code in address.png)".format(
                str(change), idx, addr, str(i)))
        print("\nControls:")
        print("    'NEXT' -- view next {} addresses".format(N))
        print("    'PREV' -- view previous {} addresses".format(N))
        print("    'CHANGE' -- toggle to/from change addresses")
        print("    'QUIT' -- quit proof wallet\n")
        cmd = input("Enter your desired command: ")

        if cmd == "NEXT":
            start += N
        elif cmd == "PREV" and start > 0:
            start -= N
        elif cmd == "CHANGE":
            change = 1 if change == 0 else 0
        elif cmd == "QUIT":
            sys.exit()
        elif cmd in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]:
            write_and_verify_qr_code("address", "address.png", addresses[int(cmd)])
        else:
            print("Unsupported option.")

################################################################################################
#
# Main "withdraw" function
#
################################################################################################
def sign_psbt_interactive(m, n, my_xprv):
    """
    Import, validate and sign a psbt to withdraw funds from cold storage.
    All data required for this operation is input at the terminal

    m: <int> number of multisig keys required for withdrawal
    n: <int> total number of multisig keys
    """

    safety_checklist()
    ensure_bitcoind_running()
    require_minimum_bitcoind_version(200100)

    # prompt user for mnemonic and all xpubs in the multisignature quorum
    if my_xprv is None:
        my_xprv = get_mnemonic_interactive()
    my_xpub = get_xpub_from_xkey(my_xprv)
    dkeys = get_descriptor_keys_interactive(n)
    xpubs = list(map(lambda dkey: dkey[2], dkeys))

    if my_xpub not in xpubs:
        print("Error: No xpubs match the xpub of the provided mnemonic phrase. Exiting.")
        sys.exit(1)
    dkeys = [
        (fng, path, xpub if xpub != my_xpub else my_xprv)
        for (fng, path, xpub)
        in dkeys
    ]

    # prompt user for base64 psbt string
    psbt_raw = input("\nEnter the psbt for the transaction you wish to sign: ")

    print("\nValidating the PSBT...")
    psbt_validation = validate_psbt(psbt_raw, dkeys, m)
    if psbt_validation["error"] is not None:
        print("Error: {}".format(psbt_validation["error"]))
        sys.exit(1)

    psbt = psbt_validation["psbt"]
    analysis = psbt_validation["analysis"]
    change_idxs = psbt_validation["change_idxs"]

    # Retrieve fields from decoded PSBT that need to be shown to user
    tx = psbt["tx"]
    txid = tx["txid"]
    num_vin = len(tx["vin"])
    num_vout = len(tx["vout"])

    fee = Decimal(psbt["fee"]).quantize(SATOSHI_PLACES)
    fee_rate_raw = Decimal(analysis["estimated_feerate"]).quantize(SATOSHI_PLACES)
    fee_rate = round(FEE_RATE_MULTIPLIER * fee_rate_raw, 1) # convert and round BTC/kB to sat/byte
    vsize = analysis["estimated_vsize"]

    # Render transaction inputs
    def parse_input(psbt, idx):
        txid = psbt["tx"]["vin"][idx]["txid"]
        vout = psbt["tx"]["vin"][idx]["vout"]
        addr = psbt["inputs"][idx]["witness_utxo"]["scriptPubKey"]["address"]
        amount = Decimal(psbt["inputs"][idx]["witness_utxo"]["amount"]).quantize(SATOSHI_PLACES)
        return (txid, vout, addr, amount)

    inputs = list(map(lambda i: parse_input(psbt, i), range(num_vin)))
    inputs_str = "Inputs ({})\n".format(num_vin)
    for txin, vout, addr, amount in inputs:
        txid_formatted = txin[:10] + "..." + txin[-10:]
        inputs_str += "{}:{}\t{}\t{}\n".format(
            txid_formatted,
            vout,
            addr,
            amount
        )

    # Render transaction outputs
    def parse_output(psbt, idx):
        change = idx in change_idxs
        [addr] = psbt["tx"]["vout"][idx]["scriptPubKey"]["addresses"]
        value = Decimal(psbt["tx"]["vout"][idx]["value"]).quantize(SATOSHI_PLACES)
        return (addr, value, change)

    amt_sent = 0
    outputs = list(map(lambda i: parse_output(psbt, i), range(num_vout)))
    outputs_str = "Outputs ({})\n".format(num_vout)
    for addr, value, change in outputs:
        change_str = "CHANGE" if change else "NOT CHANGE"
        amt_sent += 0 if change else value
        outputs_str += "[{}] {}\t{}\n".format(change_str, addr, value)

    while True:
        print(LINE_BREAK)
        if len(psbt_validation["warning"]) > 0:
            print("PSBT validation was successful, but note the following warnings before signing the transaction:")
            for warning in psbt_validation["warning"]:
                print("* {}".format(warning))
        else:
            print("PSBT validation was successful.")

        print("\n+-----------------------+")
        print("|                       |")
        print("|  Transaction Summary  |")
        print("|                       |")
        print("+-----------------------+")
        print("Transaction ID: {}".format(txid))
        print("Virtual size: {} vbyte".format(vsize))
        print("Amount sent: {}".format(amt_sent))
        print("Fee (total): {}".format(fee))
        print("Fee (rate): {} sat/byte".format(fee_rate))

        print("\n{}".format(inputs_str))
        print("{}".format(outputs_str))

        print("Controls:")
        print("    'SIGN' -- sign the transaction")
        print("    'QUIT' -- quit proof wallet without signing the transaction")
        cmd = input("\nEnter your desired command: ")

        if cmd == "SIGN":
            # sign psbt and write QR code(s)
            psbt_signed = walletprocesspsbt(psbt_raw, psbt_validation["importmulti_idxs"], dkeys, m)

            # show text of signed PSBT
            print("\nSigned psbt (base64):")
            print(psbt_signed["psbt"])

            # show PSBT md5 fingerprint
            print("\nPSBT fingerprint (md5):")
            print(hash_md5(psbt_signed["psbt"]))
            print()

            # write qr codes of signed psbt
            write_and_verify_qr_code("signed psbt", "psbt-signed.png", psbt_signed["psbt"])
            sys.exit()
        elif cmd == "QUIT":
            print("Exiting...")
            sys.exit(0)
        else:
            print("Unsupported option.\n")

################################################################################################
#
# main function
#
# Show help, or execute one of the four main routines: entropy, create-wallet, view-addresses,
# and sign-psbt
#
################################################################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser(epilog="For more help, include a subcommand, e.g. `./proofwallet.py entropy --help`")
    parser.add_argument('-v', '--verbose', action='store_true', help='increase output verbosity')

    subs = parser.add_subparsers(title='Subcommands', dest='program')

    def add_networks(parser):
        parser.add_argument('--testnet', action='store_true', help=argparse.SUPPRESS)
        parser.add_argument('--regtest', action='store_true', help=argparse.SUPPRESS)

    def add_rng(parser):
        """Add the --rng option to the parser."""
        help_text = "Minimum number of 8-bit bytes to use for computer entropy when generating private keys (default: 32)"
        parser.add_argument("-r", "--rng", type=int, help=help_text, default=32)

    def add_m(parser):
        """Add the -m option to the parser."""
        help_text = "Number of signing keys required in an m-of-n multisig wallet (default m-of-n = 1-of-2)"
        parser.add_argument("-m", type=int, help=help_text, default=1)

    def add_n(parser):
        """Add the -n option to the parser."""
        help_text = "Number of total keys required in an m-of-n multisig wallet (default m-of-n = 1-of-2)"
        parser.add_argument("-n", type=int, help=help_text, default=2)

    def add_private_file(parser):
        """Add the --private-file option to the parser"""
        help_text = "Filepath to a one line text file containing a BIP39 mnemonic"
        parser.add_argument("--private-file", type=argparse.FileType('r'), help=help_text)

    def get_xprv(args):
        my_xprv = None
        if args.private_file:
            lines = args.private_file.readlines()
            if len(lines) != 1:
                print("Error: the private-file must contain 1 line with a BIP39 mnemonic.")
                sys.exit(1)
            my_xprv = parse_mnemonic_to_master_key(lines[0])
        return my_xprv

    def validate_m_n(m, n):
        if n < 2 or n > 15:
            print("Error: n must be between 2 and 15")
            sys.exit(1)
        if m < 1 or m > n:
            print("Error: m must be between 1 and n")
            sys.exit(1)

    # Entropy parser
    parser_entropy = subs.add_parser('entropy', help="Generate computer entropy")
    add_rng(parser_entropy)
    add_networks(parser_entropy)

    # Create wallet parser
    parser_create_wallet = subs.add_parser('create-wallet', help="Create a BIP39 HD wallet")
    add_rng(parser_create_wallet)
    dice_help = "Minimum number of dice rolls to use for entropy when generating private keys (default: 100)"
    parser_create_wallet.add_argument("-d", "--dice", type=int, help=dice_help, default=100)
    parser_create_wallet.add_argument("--num-words", type=int, help="Number of words in BIP39 mnemonic", choices=[12, 24], default=24)
    add_networks(parser_create_wallet)

    # View addresses parser
    parser_view_addresses = subs.add_parser('view-addresses', help="View deposit addresses")
    add_m(parser_view_addresses)
    add_n(parser_view_addresses)
    add_networks(parser_view_addresses)
    add_private_file(parser_view_addresses)
    parser_view_addresses.add_argument("--trust-xpubs", action="store_true", help="Only prompts user for xpubs")

    # Sign psbt parser
    parser_sign_psbt = subs.add_parser('sign-psbt', help="Sign a PSBT")
    add_m(parser_sign_psbt)
    add_n(parser_sign_psbt)
    add_networks(parser_sign_psbt)
    add_private_file(parser_sign_psbt)

    args = parser.parse_args()
    verbose_mode = args.verbose

    global network, cli_args
    network = "testnet" if args.testnet else ("regtest" if args.regtest else "mainnet")
    cli_args = {
        'mainnet': [],
        'testnet': ["-testnet"],
        'regtest': ["-regtest"],
    }[network]


    if args.program == "entropy":
        entropy(args.rng)

    if args.program == "create-wallet":
        seed_length = 32 if args.num_words == 24 else 16 # in bytes
        create_wallet_interactive(args.dice, args.rng, seed_length)

    if args.program == "view-addresses":
        validate_m_n(args.m, args.n)
        view_addresses_interactive(args.m, args.n, get_xprv(args), args.trust_xpubs)

    if args.program == "sign-psbt":
        validate_m_n(args.m, args.n)
        sign_psbt_interactive(args.m, args.n, get_xprv(args))
