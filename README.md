# Solana Security Patterns

A hands-on educational resource for Solana developers to learn common smart contract vulnerabilities through working code and exploit tests.

Each pattern includes:
- **Vulnerable implementation** — Demonstrates the security flaw
- **Secure implementation** — Shows the proper fix
- **Exploit tests** — Proves the vulnerability is real and the fix works

## Patterns

| # | Pattern | Description | Real-World Reference |
|---|---------|-------------|---------------------|
| 1 | [Missing Signer Check](patterns/01-missing-signer-check/) | Failing to verify transaction signatures | Common in early Solana programs |
| 2 | [Missing Owner Check](patterns/02-missing-owner-check/) | Trusting account data without verifying ownership | Wormhole ($326M) |
| 3 | [Integer Overflow](patterns/03-integer-overflow/) | Arithmetic that wraps instead of failing | Multiple token exploits |
| 4 | [Re-initialization Attack](patterns/04-reinitialization-attack/) | Allowing accounts to be initialized twice | DeFi protocol takeovers |
| 5 | [PDA Bump Canonicalization](patterns/05-pda-bump-canonicalization/) | Accepting non-canonical bumps for PDAs | PDA uniqueness bypasses |
| 6 | [Type Cosplay](patterns/06-type-cosplay/) | Passing wrong account type with same layout | Admin privilege escalation |

## Quick Start

### Prerequisites

- Rust 1.75+
- Solana CLI 2.1+
- Anchor CLI 0.31+

### Build All Programs

```bash
# Build all Anchor programs
for dir in patterns/*/anchor; do
  cargo build-sbf --manifest-path "$dir/Cargo.toml"
done
```

### Run Exploit Tests

```bash
# Run all tests
SBF_OUT_DIR=target/deploy cargo test -- --nocapture

# Run tests for a specific pattern
SBF_OUT_DIR=target/deploy cargo test -p test-missing-signer -- --nocapture
SBF_OUT_DIR=target/deploy cargo test -p test-missing-owner -- --nocapture
SBF_OUT_DIR=target/deploy cargo test -p test-integer-overflow -- --nocapture
SBF_OUT_DIR=target/deploy cargo test -p test-reinitialization -- --nocapture
SBF_OUT_DIR=target/deploy cargo test -p test-pda-bump -- --nocapture
SBF_OUT_DIR=target/deploy cargo test -p test-type-cosplay -- --nocapture
```

## Project Structure

```
solana-security-patterns/
├── patterns/
│   ├── 01-missing-signer-check/
│   │   ├── anchor/          # Anchor program (vulnerable + secure)
│   │   ├── tests/           # Mollusk exploit tests
│   │   └── README.md        # Pattern documentation
│   ├── 02-missing-owner-check/
│   │   └── ...
│   └── ...
├── Cargo.toml               # Workspace configuration
└── README.md
```

## Testing Framework

Tests use [Mollusk](https://github.com/anza-xyz/mollusk), Anza's lightweight SVM simulator. Mollusk runs Solana programs without a full validator, making tests fast and deterministic.

Each test file demonstrates:
1. **Exploit test** — Shows the vulnerability being exploited
2. **Secure rejection test** — Shows the fix blocking the attack
3. **Sanity test** — Confirms legitimate operations still work

## How to Use This Repo

**For learning:**
1. Read a pattern's README to understand the vulnerability
2. Examine the Anchor code (`lib.rs`) — compare vulnerable vs secure
3. Run the exploit tests to see the attack succeed and fail
4. Apply the lessons to your own code

**For auditing:**
- Use these patterns as a checklist when reviewing Solana programs
- The test structure shows how to write exploit PoCs

**For teaching:**
- Each pattern is self-contained and can be presented independently
- The vulnerable/secure side-by-side comparison is designed for clarity

## Key Takeaways

| Pattern | One-Line Fix |
|---------|--------------|
| Missing Signer | Use `Signer<'info>` not `AccountInfo` |
| Missing Owner | Use `Account<T>` not `AccountInfo` |
| Integer Overflow | Use `checked_add/sub/mul/div` |
| Re-initialization | Use `init` constraint or check `is_initialized` |
| PDA Bump | Use `find_program_address`, never accept bump as input |
| Type Cosplay | Use `Account<T>` to enforce discriminator checks |

## Resources

- [Anchor Book](https://book.anchor-lang.com/)
- [Solana Cookbook - Security](https://solanacookbook.com/references/programs.html#how-to-verify-accounts)
- [Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks)
- [Neodyme Blog](https://blog.neodyme.io/)

## License

MIT
