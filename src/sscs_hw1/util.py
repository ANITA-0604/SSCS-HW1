"""
Utility functions for signature verification and key extraction.
"""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm


def extract_public_key(cert):
    """Extract a PEM-encoded public key from a PEM certificate.

    Args:
        cert: Certificate in PEM-encoded bytes.

    Returns:
        bytes: Public key encoded in PEM (SubjectPublicKeyInfo).
    """

    # read the certificate
    #    with open("cert.pem", "rb") as cert_file:
    #        cert_data = cert_file.read()

    # load the certificate
    certificate = x509.load_pem_x509_certificate(cert, default_backend())

    # extract the public key
    public_key = certificate.public_key()

    # save the public key to a PEM file
    #    with open("cert_public.pem", "wb") as pub_key_file:
    #        pub_key_file.write(public_key.public_bytes(
    #            encoding=serialization.Encoding.PEM,
    #            format=serialization.PublicFormat.SubjectPublicKeyInfo
    #        ))
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return pem_public_key


def verify_artifact_signature(signature, public_key, artifact_filename):
    """Verify an ECDSA SHA-256 signature for an artifact file.

    Args:
        signature: Raw signature bytes produced over the artifact content.
        public_key: PEM-encoded public key bytes used to verify the signature.
        artifact_filename: Path to the artifact file whose contents were signed.

    Side Effects:
        Prints a message if the signature is invalid or if an exception occurs.

    Note:
        This function does not return a value; it raises no exception on
        verification failure and instead prints an error message.
    """
    # load the public key
    # with open("cert_public.pem", "rb") as pub_key_file:
    #    public_key = load_pem_public_key(pub_key_file.read())

    # load the signature
    #    with open("hello.sig", "rb") as sig_file:
    #        signature = sig_file.read()

    

    # verify the signature
    try:
        public_key = load_pem_public_key(public_key)
        # load the data to be verified
        with open(artifact_filename, "rb") as data_file:
            data = data_file.read()
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("Signature is invalid")
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        print("Exception in verifying artifact signature:", e)
