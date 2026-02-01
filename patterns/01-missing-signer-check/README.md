# Pattern 1: Missing Signer Check

**Failing to verify that an account actually signed the transaction.**

## The Vulnerability

When a program checks that an account's pubkey matches an expected authority but doesn't verify the signature, anyone can pass any pubkey as the "authority." The instruction succeeds even though that authority never approved the transaction.

## Real-World Impact

This is one of the most common Solana vulnerabilities. Attackers can drain vaults, modify protocol state, or execute privileged operations by simply passing a victim's pubkey—no private key needed.

## Vulnerable Code

```rust
#[derive(Accounts)]
pub struct WithdrawVulnerable<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,

    /// CHECK: VULNERABLE - AccountInfo doesn't verify signatures!
    pub authority: AccountInfo<'info>,  // <-- Anyone can pass any pubkey

    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}
```

The `has_one = authority` constraint only checks that `vault.authority == authority.key()`. It does **not** verify that `authority` signed the transaction.

## Secure Code

```rust
#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,

    pub authority: Signer<'info>,  // <-- MUST have signed the transaction

    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}
```

## The Fix

Change `AccountInfo<'info>` to `Signer<'info>`. Anchor automatically verifies the signature exists before your instruction code runs. No signature = transaction rejected.

## Test It

```bash
# Build the program
cargo build-sbf --manifest-path patterns/01-missing-signer-check/anchor/Cargo.toml

# Run exploit tests
SBF_OUT_DIR=target/deploy cargo test -p test-missing-signer -- --nocapture
```

**What the tests prove:**
- `exploit_withdraw_without_signer` — Attacker withdraws funds without signing (vulnerability confirmed)
- `secure_rejects_unsigned_withdraw` — Secure version rejects unsigned withdrawal (error 3010: AccountNotSigner)
- `secure_allows_signed_withdraw` — Legitimate signed withdrawal succeeds

## Pinocchio Version

In Pinocchio, there's no `Signer<'info>` type. You must manually check `is_signer()`:

```rust
// VULNERABLE: No signer check
fn withdraw_vulnerable(accounts: &[AccountInfo], ...) -> ProgramResult {
    let authority = &accounts[1];

    // Only checks pubkey match - NOT signature!
    if stored_authority != *authority.key() {
        return Err(ProgramError::Custom(ERR_INVALID_AUTHORITY));
    }
    // Missing: authority.is_signer() check
    // ...
}

// SECURE: Explicit signer check
fn withdraw_secure(accounts: &[AccountInfo], ...) -> ProgramResult {
    let authority = &accounts[1];

    // SECURE: Check signature FIRST
    if !authority.is_signer() {
        return Err(ProgramError::Custom(ERR_MISSING_SIGNER));
    }
    // Then check pubkey match
    // ...
}
```

Build: `cargo build-sbf --manifest-path patterns/01-missing-signer-check/pinocchio/Cargo.toml`

## Key Takeaway

**`has_one` checks the pubkey. `Signer<'info>` (Anchor) or `is_signer()` (Pinocchio) checks the signature. You need both.**
