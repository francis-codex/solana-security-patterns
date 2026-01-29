# Pattern 5: PDA Bump Seed Canonicalization

**Accepting user-supplied bumps instead of enforcing the canonical bump, breaking PDA uniqueness.**

## The Vulnerability

`Pubkey::find_program_address` returns the **canonical bump**—the highest valid bump (255 down to 0) that produces an off-curve point. But `Pubkey::create_program_address` accepts *any* valid bump.

If a program accepts a user-supplied bump without enforcing the canonical one, multiple valid PDAs can exist for the same seeds. An attacker can:

- Create duplicate accounts at different bumps
- Store conflicting data that confuses lookups
- Bypass uniqueness constraints the program assumes

## Real-World Impact

Programs that use PDAs for user vaults, configs, or escrows assume one PDA per seed set. If an attacker can create accounts at non-canonical bumps, they can:
- Create a "shadow" vault that the legitimate user doesn't know about
- Confuse the program about which account is authoritative
- Potentially drain funds by manipulating which PDA is read vs. written

## Vulnerable Code

```rust
pub fn set_value_vulnerable(
    ctx: Context<SetValueVulnerable>,
    bump: u8,  // <-- User-supplied bump
    value: u64,
) -> Result<()> {
    // VULNERABLE: Uses whatever bump the caller provides
    let seeds = &[b"data", ctx.accounts.user.key.as_ref(), &[bump]];
    let pda = Pubkey::create_program_address(seeds, ctx.program_id)?;

    // This check passes for ANY valid bump, not just canonical
    require_keys_eq!(pda, ctx.accounts.data_account.key());

    let data_account = &mut ctx.accounts.data_account;
    data_account.value = value;
    data_account.bump = bump;  // Stores non-canonical bump

    Ok(())
}
```

## Secure Code

```rust
pub fn set_value_secure(
    ctx: Context<SetValueSecure>,
    value: u64,
) -> Result<()> {
    // SECURE: Derive canonical bump (highest valid bump)
    let (expected_pda, canonical_bump) = Pubkey::find_program_address(
        &[b"data", ctx.accounts.user.key.as_ref()],
        ctx.program_id,
    );

    // Only the canonical PDA is accepted
    require_keys_eq!(expected_pda, ctx.accounts.data_account.key());

    let data_account = &mut ctx.accounts.data_account;
    data_account.value = value;
    data_account.bump = canonical_bump;  // Always canonical

    Ok(())
}

// OR use Anchor's seeds constraint (framework-idiomatic):
#[derive(Accounts)]
pub struct SetValueAnchor<'info> {
    #[account(mut, seeds = [b"data", user.key().as_ref()], bump)]
    pub data_account: Account<'info, DataAccount>,  // <-- Anchor enforces canonical bump
    pub user: Signer<'info>,
}
```

## The Fix

1. **Use `find_program_address`** to derive the canonical bump on-chain
2. **Reject any PDA** that doesn't match the canonical derivation
3. **Or use Anchor's `seeds` + `bump` constraint** — it auto-enforces canonicalization

Never accept a user-supplied bump argument. The canonical bump should be derived, not provided.

## Test It

```bash
# Build the program
cargo build-sbf --manifest-path patterns/05-pda-bump-canonicalization/anchor/Cargo.toml

# Run exploit tests
SBF_OUT_DIR=target/deploy cargo test -p test-pda-bump -- --nocapture
```

**What the tests prove:**
- `exploit_non_canonical_bump_accepted` — Non-canonical bump (e.g., 251) is accepted, creating a duplicate PDA
- `secure_rejects_non_canonical_bump` — Secure version rejects non-canonical PDA (error 6001: PdaMismatch)
- `secure_accepts_canonical_bump` — Canonical bump works correctly

## Key Takeaway

**One seed set = one canonical PDA. Derive the bump with `find_program_address`, never accept it as input.**
