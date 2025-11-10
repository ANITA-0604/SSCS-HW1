# Contributing Guidelines

Thank you for your interest in contributing to this project!  
This repository is part of the **Software Supply Chain Security** assignment and follows strict code quality and security practices.

## How to Contribute

1. **Fork the repository** and create a new branch for your feature or bug fix.

   ```
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** on your own feature branch
   and commit them with clearly descriptive message. For exmaple :
   ```
   git commit -m "Add function to verify Rekor inclusion proof"
   ```
3. **Run all test** before pushing your changes:

   ```
   pytest
   ```

4. **Push your fork** and open a **Pull Request(PR)** to the main branch
   4.1. Ensure your branch is up-to-date with `main`
   ```
   git pull origin main
   ```
   4.2. Submit your PR with a clear description of your changes and why they’re needed.

## Testing Requirement

## Code Style

## Security Consideration

## Code Review Process

- All pull requests require **at least one approval** (from yourself, as the repository owner).
- The main branch is protected and only allows merges through pull requests.
- Ensure linear commit history and clean commit messages.
