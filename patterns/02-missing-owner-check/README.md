# Pattern 2: Missing Owner Check

**Trusting account data without verifying who owns the account.**

## The Vulnerability

On Solana, any program can create accounts with arbitrary data. If your program reads account data without verifying the account's `owner` field, an attacker can craft a fake account with matching byte layout and pass it in. Your program deserializes it and trusts completely fabricated data.

## Real-World Impact: Wormhole Bridge Hack ($326M)

In February 2022, the Wormhole bridge was exploited because it accepted a spoofed "SignatureSet" account that was **not owned by the Wormhole program**. The attacker created a fake account with data matching the expected layout, bypassing all validation except ownership. Result: $326 million stolen.

## Vulnerable Code

```rust
#[derive(Accounts)]
pub struct ProcessVulnerable<'info> {
    /// CHECK: VULNERABLE - no owner verification!
    pub treasury: AccountInfo<'info>,  // <-- Could be owned by ANY program
    pub authority: Signer<'info>,
}

pub fn process_vulnerable(ctx: Context<ProcessVulnerable>) -> Result<()> {
    let data = ctx.accounts.treasury.try_borrow_data()?;
    // Manually deserialize... but this data could be completely fake
    let balance = u64::from_le_bytes(data[40..48].try_into()?);
    // Program trusts the fake balance
}
```

## Secure Code

```rust
#[derive(Accounts)]
pub struct ProcessSecure<'info> {
    #[account(has_one = authority)]
    pub treasury: Account<'info, Treasury>,  // <-- Anchor verifies owner
    pub authority: Signer<'info>,
}
```

## The Fix

Use `Account<'info, T>` instead of `AccountInfo`. Anchor automatically verifies:
1. The account is owned by your program (`owner == program_id`)
2. The 8-byte discriminator matches the expected type
3. The data deserializes correctly

## Test It

```bash
# Build the program
cargo build-sbf --manifest-path patterns/02-missing-owner-check/anchor/Cargo.toml

# Run exploit tests
SBF_OUT_DIR=target/deploy cargo test -p test-missing-owner -- --nocapture
```

**What the tests prove:**
- `exploit_fake_account_accepted` — Fake account (owned by system program) is accepted by vulnerable instruction
- `secure_rejects_fake_account` — Secure version rejects wrong owner (error 3007: AccountOwnedByWrongProgram)
- `secure_accepts_real_treasury` — Legitimate program-owned treasury works fine

## Key Takeaway

**`AccountInfo` gives you bytes. `Account<T>` gives you verified, trusted data. The Wormhole hack happened because of this difference.**
