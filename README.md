# SSCS-HW1 - Software Supply Chain Security Assignment 1

[![CI](https://github.com/ANITA-0604/SSCS-HW1/actions/workflows/ci.yml/badge.svg)](https://github.com/ANITA-0604/SSCS-HW1/actions/workflows/ci.yml)
[![Scorecard](https://github.com/ANITA-0604/SSCS-HW1/actions/workflows/scorecard.yml/badge.svg)](https://github.com/ANITA-0604/SSCS-HW1/actions/workflows/scorecard.yml)

## Overview

This project implements a software supply chain security workflow using Sigstore’s Rekor transparency log.
It demonstrates how artifacts can be signed, verified, and validated for integrity to ensure a secure and tamper-resistant software release process.

The project covers three core areas of software supply chain security:

### 1. Artifact Signing & Transparency Log Upload

Using Sigstore’s cosign, artifacts are signed with an ephemeral certificate tied to the developer’s identity, and signatures are uploaded to Rekor, a public transparency log.

### 2. Log Entry Verification & Merkle Inclusion Proof

The project retrieves log entry data from Rekor, extracts the certificate and signature, verifies the artifact’s integrity using the public key, and validates the Merkle inclusion proof to confirm that the entry exists within the Rekor log.

### 3. Checkpoint Consistency Verification

The Rekor log is treated as an append-only tamper-proof log.
The project verifies the consistency between past and latest checkpoints using Merkle tree proofs, ensuring that no previous log history has been altered.

This project forms the foundation for future assignments, which will further enhance the security, quality, and maintainability of this repository.

## Installation

### 1. Install all required dependencies:

```
pip install -r requirements.txt
```

### 2. If you are using Homebrew (or Linuxbrew), install Cosign:

```
brew install cosign
```

For other environments, refer to
https://docs.sigstore.dev/cosign/system_config/installation/

## Example Usage

### 1. Sign an artifact (e.g. artifact.md) using Cosign:

```
cosign sign-blob artifact.md --bundle artifact.bundle
```

To see the signing info and log index:

```
tail -n6 artifact.bundle
```

### 2. Fetch the latest Rekor checkpoint:

```
python main.py -c
```

### 3. Verify artifact inclusion and signature:

```
python main.py --inclusion {logIndex} --artifact artifact.md
```

### 4. Verify checkpoint consistency:

```
python main.py --consistency --tree-id {tree-id} --tree-size {tree-size} --root-hash {root-hash}
```

## Contributing Guideline

To learn about pull requests, testing requirements, and coding standards, see CONTRIBUTING.md.

## Security Policy

Please refer to SECURITY.md for details about:

- Supported versions
- Reporting vulnerabilities
- Responsible disclosure policy

## Branch Protection Rules

The main branch is protected to ensure secure and traceable development practices.
The following protection rules have been applied:

- Pull requests are required before merging.
- At least one code review approval is required.
- Branches must be up to date before merging.
- Linear commit history is enforced.
- Signed commits are required.

These configurations prevent direct pushes to the main branch and enforce code review and integrity verification in the development workflow.

## License

This project is licensed under the MIT License.

## Contact / Support

If you encounter issues or have improvement suggestions, please open an issue or reach out through the course platform.
