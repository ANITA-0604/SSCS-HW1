"""
Rekor transparency log verifier.

This module provides functionality to verify inclusion and consistency
proofs from the Rekor transparency log.
"""
import argparse
import base64
import json

import binascii
import requests


from sscs_hw1.util import extract_public_key, verify_artifact_signature
from sscs_hw1.merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
    RootMismatchError,
)

REKOR_BASE_URL = "https://rekor.sigstore.dev/api/v1"


def get_log_entry(log_index, debug=False):
    """Fetch a Rekor log entry by index.

    Args:
        log_index: Integer index of the entry in the Rekor log.
        debug: Whether to print debug information.

    Returns:
        dict | None: JSON object returned by Rekor keyed by entry UUID,
        or None if the request fails or no entry is found.
    """
    try:
        response = requests.get(f"{REKOR_BASE_URL}/log/entries?logIndex={log_index}", timeout=5)
        response.raise_for_status()
        data = response.json()
        if not data:
            if debug:
                print(f"No entry found at log index {log_index}")
            return None
        return data
    except requests.exceptions.RequestException as e:
        print("Request failed:", e)
        return None


def get_verification_proof(log_index, debug=False):
    """Retrieve the inclusion/verification proof for a log entry.

    Args:
        log_index: Integer index of the entry in the Rekor log.
        debug: Whether to print debug information.

    Returns:
        dict | None: Proof payload for the entry (by UUID) or None on error.
    """
    try:
        log_data = get_log_entry(log_index)
        if not log_data:
            if debug:
                print(f"No entry found at log index {log_index}")
            return None

        uuid = list(log_data.keys())[0]

        response = requests.get(f"{REKOR_BASE_URL}/log/entries/{uuid}", timeout=5)
        response.raise_for_status()
        proof_data = response.json()

        if debug:
            print("Verification proof:")
            print(json.dumps(proof_data, indent=4))

        return proof_data
    except (requests.exceptions.RequestException, ValueError) as e:
        print("Error fetching verification proof:", e)
        return None


def inclusion(log_index, artifact_filepath, debug=False):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """Verify the artifact’s signature and its inclusion proof.

    Steps:
    - Downloads the Rekor entry at `log_index`.
    - Extracts the signature and certificate; derives the public key.
    - Verifies the artifact signature.
    - Fetches the inclusion proof and validates it against the computed leaf.

    Args:
        log_index: Rekor log index of the entry to verify.
        artifact_filepath: Path to the artifact file whose signature is recorded.
        debug: Whether to print debug information.

    Returns:
        bool: True if verification steps complete without errors; False on failure.
    """

    try:
        with open(artifact_filepath, "rb") as _:
            pass
    except FileNotFoundError:
        if debug:
            print(f"Artifact file not found: {artifact_filepath}")
        return False
    except OSError as e:
        if debug:
            print(f"Error accessing artifact file: {e}")
        return False
    print(log_index)
    log_data = get_log_entry(log_index, debug)
    if not log_data:
        if debug:
            print("Failed to get log entry data")
        return False

    try:
        # Extract signature and certificate from log entry
        uuid = list(log_data.keys())[0]
        body_encoded = log_data[uuid].get("body")
        body_decoded = base64.b64decode(body_encoded)
        body_json = json.loads(body_decoded)
        if debug:
            print(body_json)

        # Extract signature

        signature_encoded = (
            body_json.get("spec", {}).get("signature", {}).get("content")
        )
        signature_decoded = base64.b64decode(signature_encoded)

        if debug:
            print(signature_decoded)

        # Extract certificate

        certificate_encoded = (
            body_json.get("spec", {})
            .get("signature", {})
            .get("publicKey", {})
            .get("content")
        )
        certificate_decoded = base64.b64decode(certificate_encoded)

        if debug:
            print(certificate_decoded)

        # Extract public key
        public_key = extract_public_key(certificate_decoded)
        if debug:
            print(public_key)

        verify_artifact_signature(signature_decoded, public_key, artifact_filepath)
        print("Signature is valid")

        proof = get_verification_proof(log_index)
        if proof is None:
            if debug:
                print("It fails to get verification proof")
            return False
        uuid = list(proof.keys())[0]  # get the entry key
        entry = proof[uuid]

        inclusion_proof = entry.get("verification", {}).get("inclusionProof", {})
        if debug:
            print("Finish getting proof")

        # compute leaf hash
        leaf_hash = compute_leaf_hash(body_encoded)  # usually hex string
        index = inclusion_proof.get("logIndex")  # integer
        root_hash = inclusion_proof.get("rootHash")  # hex string
        tree_size = inclusion_proof.get("treeSize")  # integer
        hashes = inclusion_proof.get("hashes", [])  # list of hex strings

        if debug:
            print("Index: ", index)
            print("leaf hash: ", leaf_hash)
            print("tree size: ", tree_size)
            print("hashes: ", hashes)
            print("root hash: ", root_hash)

        verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)

        print("Offline root hash calculation for inclusion verified.")

    except (ValueError, KeyError, binascii.Error, RootMismatchError) as e:
        print("Inclusion verification error:", e)
        return False
    return True


def get_latest_checkpoint(debug=False):
    """Fetch the latest Rekor log checkpoint.

    Args:
        debug: Whether to print debug information.

    Returns:
        dict | None: Latest checkpoint JSON including `treeSize`, `rootHash`,
        and `treeID`; None if the request fails.
    """
    try:
        response = requests.get(f"{REKOR_BASE_URL}/log", timeout=5)
        response.raise_for_status()
        data = response.json()
        if not data:
            if debug:
                print('No entry found')
            return None
        return data
    except requests.exceptions.RequestException as e:
        print("Request failed:", e)
        return None


def consistency(prev_checkpoint, debug=False):
    """Verify consistency between a previous and the latest checkpoint.

    Args:
        prev_checkpoint: Dict with keys `treeID`, `treeSize`, and `rootHash`.
        debug: Whether to print debug information.

    Returns:
        bool: True if the consistency proof verifies; False otherwise.
    """
    latest_checkpoint = get_latest_checkpoint()
    if not latest_checkpoint:
        if debug:
            print("Failed to fetch latest checkpoint")
        return False
    size1 = prev_checkpoint["treeSize"]
    root1 = prev_checkpoint["rootHash"]

    size2 = latest_checkpoint["treeSize"]
    root2 = latest_checkpoint["rootHash"]
    tree_id = latest_checkpoint["treeID"]

    if debug:
        print(f"Prev tree size: {size1}, Prev root: {root1}")
        print(f"Latest tree size: {size2}, Latest root: {root2}")

    # Fetch consistency proof from Rekor
    response = requests.get(
        f"{REKOR_BASE_URL}/log/proof?firstSize={size1}&lastSize={size2}&treeID={tree_id}", timeout=5
    )
    response.raise_for_status()
    proof_data = response.json()

    if debug:
        print("Consistency proof:")
        print(json.dumps(proof_data, indent=4))

    proof = proof_data.get("hashes", [])
    if not proof:
        print("No consistency proof found")
        return False

    # Verify consistency
    try:
        verify_consistency(DefaultHasher, size1, size2, proof, root1, root2)
        print("Consistency proof verified successfully!")
        return True
    except (ValueError, RootMismatchError) as e:
        print("Error: cannot verify consistency:", e)
        return False



def main():
    """Command-line entry for Rekor verification utilities.

    Parses arguments to:
    - Print the latest checkpoint (`--checkpoint`).
    - Verify entry inclusion for an artifact (`--inclusion` with `--artifact`).
    - Verify consistency from a provided checkpoint (`--consistency` with
      `--tree-id`, `--tree-size`, `--root-hash`).
    """
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )  # Default false
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint\
                        from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying\
                        signature",
        required=False,
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given\
                        checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:

        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()
