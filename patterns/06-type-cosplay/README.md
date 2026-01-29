# Pattern 6: Type Cosplay (Account Confusion)

**Passing an account of the wrong type that has the same binary layout, bypassing authorization.**

## The Vulnerability

When a program reads account data using `AccountInfo` or `UncheckedAccount` without checking the 8-byte Anchor discriminator, an attacker can pass an account of a **different type** that has the same field layout.

If `AdminConfig` and `UserData` both have a `Pubkey` at offset 8:

```
AdminConfig: [8-byte disc][admin: Pubkey][fee: u64]
UserData:    [8-byte disc][authority: Pubkey][balance: u64]
```

An attacker creates a `UserData` with `authority = attacker_key`, passes it where `AdminConfig` is expected, and the program reads `attacker_key` as the "admin."

## Real-World Impact

Type cosplay attacks have been used to bypass admin checks, steal funds from treasuries, and manipulate protocol parameters. Any program that manually deserializes account data without discriminator validation is vulnerable.

## Vulnerable Code

```rust
#[derive(Accounts)]
pub struct UpdateFeeVulnerable<'info> {
    /// CHECK: VULNERABLE - no discriminator check!
    #[account(mut)]
    pub config: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

pub fn update_fee_vulnerable(ctx: Context<UpdateFeeVulnerable>, new_fee: u64) -> Result<()> {
    let data = ctx.accounts.config.try_borrow_data()?;

    // VULNERABLE: Reads Pubkey at offset 8 without checking discriminator
    let admin = Pubkey::from(&data[8..40]);

    // This passes if attacker's UserData.authority matches the signer
    require_keys_eq!(admin, ctx.accounts.authority.key());

    // Attacker now controls "admin" operations
    Ok(())
}
```

## Secure Code

```rust
#[derive(Accounts)]
pub struct UpdateFeeSecure<'info> {
    #[account(mut)]
    pub config: Account<'info, AdminConfig>,  // <-- Anchor checks discriminator
    pub authority: Signer<'info>,
}

pub fn update_fee_secure(ctx: Context<UpdateFeeSecure>, new_fee: u64) -> Result<()> {
    let config = &mut ctx.accounts.config;

    // SECURE: Anchor already verified this IS an AdminConfig
    // A UserData account was rejected before reaching this code
    require_keys_eq!(config.admin, ctx.accounts.authority.key());

    config.fee_basis_points = new_fee;
    Ok(())
}
```

## The Fix

Use `Account<'info, T>` instead of `UncheckedAccount` or `AccountInfo`. Anchor automatically verifies the 8-byte discriminator matches the expected type:

- `AdminConfig` → `sha256("account:AdminConfig")[..8]`
- `UserData` → `sha256("account:UserData")[..8]`

These are completely different values. A `UserData` account will be rejected when passed to an instruction expecting `Account<AdminConfig>`.

## Test It

```bash
# Build the program
cargo build-sbf --manifest-path patterns/06-type-cosplay/anchor/Cargo.toml

# Run exploit tests
SBF_OUT_DIR=target/deploy cargo test -p test-type-cosplay -- --nocapture
```

**What the tests prove:**
- `exploit_type_cosplay_accepted` — UserData masquerades as AdminConfig, attacker updates fees
- `secure_rejects_wrong_discriminator` — Secure version rejects wrong type (error 3002: AccountDiscriminatorMismatch)
- `secure_accepts_real_admin_config` — Real AdminConfig with correct admin works fine

## Key Takeaway

**Same layout ≠ same type. The 8-byte discriminator is what distinguishes account types. Always use `Account<T>` to enforce type safety.**
