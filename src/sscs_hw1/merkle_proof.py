"""
Merkle tree proof verification utilities.

Implements RFC 6962 compliance for Merkle tree operations.
"""

import hashlib
import binascii
import base64

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1


class Hasher:
    """Hasher implementing RFC6962 domain-separated hashing operations.

    Provides helpers to compute leaf and node hashes using an underlying
    hash function (SHA-256 by default) with RFC6962 prefixes.
    """

    def __init__(self, hash_func=hashlib.sha256):
        """Initialize the hasher.

        Args:
            hash_func: Callable returning a new hash object (default: sha256).
        """
        self.hash_func = hash_func

    def new(self):
        """Return a new hash object from the configured hash function."""
        return self.hash_func()

    def empty_root(self):
        """Return the digest representing the empty tree root."""
        return self.new().digest()

    def hash_leaf(self, leaf):
        """Compute the RFC6962 leaf hash for the given leaf bytes.

        Args:
            leaf: Raw leaf bytes.

        Returns:
            bytes: The leaf hash digest.
        """
        h = self.new()
        h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        h.update(leaf)
        return h.digest()

    def hash_children(self, left, right):
        """Compute the RFC6962 node hash from left and right child hashes.

        Args:
            left: Left child hash bytes.
            right: Right child hash bytes.

        Returns:
            bytes: The parent node hash digest.
        """
        h = self.new()
        b = bytes([RFC6962_NODE_HASH_PREFIX]) + left + right
        h.update(b)
        return h.digest()

    def size(self):
        """Return the digest size in bytes for the configured hash function."""
        return self.new().digest_size


# DefaultHasher is a SHA256 based LogHasher
DefaultHasher = Hasher(hashlib.sha256)


def verify_consistency(
    hasher, size1, size2, proof, root1, root2
):  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    """Verify a consistency proof between two tree snapshots.

    Args:
        hasher: A `Hasher` instance providing hash operations.
        size1: Size of the earlier tree (int).
        size2: Size of the later tree (int).
        proof: List of hex-encoded node hashes comprising the proof.
        root1: Hex-encoded expected root hash for the earlier tree.
        root2: Hex-encoded expected root hash for the later tree.

    Raises:
        ValueError: If inputs are invalid or the proof size is incorrect.
        RootMismatchError: If calculated roots do not match the provided ones.
    """
    # change format of args to be bytearray instead of hex strings
    root1 = bytes.fromhex(root1)
    root2 = bytes.fromhex(root2)
    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    if size2 < size1:
        raise ValueError(f"size2 ({size2}) < size1 ({size1})")
    if size1 == size2:
        if bytearray_proof:
            raise ValueError("size1=size2, but bytearray_proof is not empty")
        verify_match(root1, root2)
        return
    if size1 == 0:
        if bytearray_proof:
            raise ValueError(
                f"expected empty bytearray_proof, but got {len(bytearray_proof)} components"
            )
        return
    if not bytearray_proof:
        raise ValueError("empty bytearray_proof")

    inner, border = decomp_incl_proof(size1 - 1, size2)
    shift = (size1 & -size1).bit_length() - 1
    inner -= shift

    if size1 == 1 << shift:
        seed, start = root1, 0
    else:
        seed, start = bytearray_proof[0], 1

    if len(bytearray_proof) != start + inner + border:
        raise ValueError(
            f"wrong bytearray_proof size {len(bytearray_proof)}, want {start + inner + border}"
        )

    bytearray_proof = bytearray_proof[start:]

    mask = (size1 - 1) >> shift
    hash1 = chain_inner_right(hasher, seed, bytearray_proof[:inner], mask)
    hash1 = chain_border_right(hasher, hash1, bytearray_proof[inner:])
    verify_match(hash1, root1)

    hash2 = chain_inner(hasher, seed, bytearray_proof[:inner], mask)
    hash2 = chain_border_right(hasher, hash2, bytearray_proof[inner:])
    verify_match(hash2, root2)


def verify_match(calculated, expected):
    """Raise if two digests do not match.

    Args:
        calculated: Calculated digest bytes.
        expected: Expected digest bytes.

    Raises:
        RootMismatchError: When the digests differ.
    """
    if calculated != expected:
        raise RootMismatchError(expected, calculated)


def decomp_incl_proof(index, size):
    """Decompose inclusion proof into inner and border lengths.

    Args:
        index: Leaf index in the tree (int).
        size: Total size of the tree (int).

    Returns:
        tuple[int, int]: Number of inner and border proof elements.
    """
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def inner_proof_size(index, size):
    """Return the number of inner nodes required in a proof.

    Args:
        index: Leaf index (int).
        size: Tree size (int).

    Returns:
        int: Inner proof length derived from index and size.
    """
    return (index ^ (size - 1)).bit_length()


def chain_inner(hasher, seed, proof, index):
    """Fold inner portion of a proof guided by index bits.

    Args:
        hasher: A `Hasher` instance.
        seed: Starting hash (bytes).
        proof: Iterable of sibling hashes (bytes).
        index: Leaf index used to decide ordering (int).

    Returns:
        bytes: Resulting hash after folding inner proof elements.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, h)
        else:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_inner_right(hasher, seed, proof, index):
    """Fold inner proof taking only right-branch contributions.

    Args:
        hasher: A `Hasher` instance.
        seed: Starting hash (bytes).
        proof: Iterable of sibling hashes (bytes).
        index: Leaf index to select right branches (int).

    Returns:
        bytes: Resulting hash after folding matching right branches.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_border_right(hasher, seed, proof):
    """Fold the border portion of a proof to the right.

    Args:
        hasher: A `Hasher` instance.
        seed: Starting hash (bytes).
        proof: Iterable of sibling hashes (bytes).

    Returns:
        bytes: Resulting hash after folding border proof elements.
    """
    for h in proof:
        seed = hasher.hash_children(h, seed)
    return seed


class RootMismatchError(Exception):
    """Error raised when a calculated root does not match the expected root."""

    def __init__(self, expected_root, calculated_root):
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

    def __str__(self):
        """Return a readable mismatch description."""
        return (
            "calculated root:\n"
            f"{self.calculated_root}\n"
            " does not match expected root:\n"
            f"{self.expected_root}"
        )


def root_from_inclusion_proof(hasher, index, size, leaf_hash, proof):
    """Compute the Merkle root from an inclusion proof.

    Args:
        hasher: A `Hasher` instance.
        index: Leaf index (int).
        size: Tree size (int).
        leaf_hash: Leaf hash bytes.
        proof: Iterable of sibling hashes (bytes) for the proof.

    Returns:
        bytes: The calculated Merkle root digest.

    Raises:
        ValueError: For invalid sizes or proof lengths.
    """
    if index >= size:
        raise ValueError(f"index is beyond size: {index} >= {size}")

    if len(leaf_hash) != hasher.size():
        raise ValueError(
            f"leaf_hash has unexpected size {len(leaf_hash)}, want {hasher.size()}"
        )

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {inner + border}")

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res


def verify_inclusion(
    hasher, index, size, leaf_hash, proof, root, debug=False
):  # pylint: disable=too-many-arguments,too-many-positional-arguments
    """Verify an inclusion proof for a leaf and expected root.

    Args:
        hasher: A `Hasher` instance.
        index: Leaf index (int).
        size: Tree size (int).
        leaf_hash: Hex-encoded leaf hash string.
        proof: List of hex-encoded sibling hashes.
        root: Hex-encoded expected Merkle root.
        debug: Whether to print debug information (bool).

    Raises:
        RootMismatchError: If the derived root does not match the provided one.
    """
    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    bytearray_root = bytes.fromhex(root)
    bytearray_leaf = bytes.fromhex(leaf_hash)
    calc_root = root_from_inclusion_proof(
        hasher, index, size, bytearray_leaf, bytearray_proof
    )
    verify_match(calc_root, bytearray_root)
    if debug:
        print("Calculated root hash", calc_root.hex())
        print("Given root hash", bytearray_root.hex())


# requires entry["body"] output for a log entry
# returns the leaf hash according to the rfc 6962 spec
def compute_leaf_hash(body):
    """Compute the RFC6962 leaf hash for a base64-encoded entry body.

    Args:
        body: Base64-encoded body bytes (as returned in Rekor entries).

    Returns:
        str: Hex-encoded leaf hash string.
    """
    entry_bytes = base64.b64decode(body)

    # create a new sha256 hash object
    h = hashlib.sha256()
    # write the leaf hash prefix
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))

    # write the actual leaf data
    h.update(entry_bytes)

    # return the computed hash
    return h.hexdigest()
