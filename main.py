import argparse
from util import extract_public_key, verify_artifact_signature
from merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
)
import json
import requests
import base64

REKOR_BASE_URL = "https://rekor.sigstore.dev/api/v1"


def get_log_entry(log_index, debug=False):
    # verify that log index value is sane
    try:
        response = requests.get(f"{REKOR_BASE_URL}/log/entries?logIndex={log_index}")
        response.raise_for_status()
        data = response.json()
        if not data:
            if debug:
                print(f"No entry found at log index {log_index}")
            return None
        return data
    except requests.exceptions.RequestException as e:
        print("Request failed:", e)


def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
    try:
        log_data = get_log_entry(log_index)
        if not log_data:
            if debug:
                print(f"No entry found at log index {log_index}")
            return None

        uuid = list(log_data.keys())[0]

        response = requests.get(f"{REKOR_BASE_URL}/log/entries/{uuid}")
        response.raise_for_status()
        proof_data = response.json()

        if debug:
            print("Verification proof:")
            print(json.dumps(proof_data, indent=4))

        return proof_data
    except Exception as e:
        print("Error: ", e)


def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane

    try:
        # Check if artifact file exists
        with open(artifact_filepath, "rb") as f:
            pass
    except FileNotFoundError:
        if debug:
            print(f"Artifact file not found: {artifact_filepath}")
        return False
    except Exception as e:
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

    except Exception as e:
        print("Error: ", e)


def get_latest_checkpoint(debug=False):
    try:
        response = requests.get(f"{REKOR_BASE_URL}/log")
        response.raise_for_status()
        data = response.json()
        if not data:
            if debug:
                print(f"No entry found")
            return None
        return data
    except requests.exceptions.RequestException as e:
        print("Request failed:", e)


def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    latest_checkpoint = get_latest_checkpoint()
    if not latest_checkpoint and debug:
        print("Failed to fetch latest checkpoint")
        return False
    size1 = prev_checkpoint["treeSize"]
    root1 = prev_checkpoint["rootHash"]

    size2 = latest_checkpoint["treeSize"]
    root2 = latest_checkpoint["rootHash"]
    treeID = latest_checkpoint["treeID"]

    if debug:
        print(f"Prev tree size: {size1}, Prev root: {root1}")
        print(f"Latest tree size: {size2}, Latest root: {root2}")

    # Fetch consistency proof from Rekor
    response = requests.get(
        f"{REKOR_BASE_URL}/log/proof?firstSize={size1}&lastSize={size2}&treeID={treeID}"
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
    except Exception as e:
        print("Error: cannot verify consistency")
    return True


def main():
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
