# Pattern 3: Integer Overflow/Underflow

**Arithmetic that wraps around instead of failing, breaking accounting invariants.**

## The Vulnerability

Rust's release builds wrap on overflow by default. Solana BPF programs compile in release mode, so `u64::MAX + 1` silently becomes `0`, and `0 - 1` becomes `u64::MAX`. Attackers exploit this to:

- **Overflow supply**: `supply + mint_amount` wraps to zero, allowing infinite minting
- **Underflow balance**: `balance - withdraw` wraps to `u64::MAX`, bypassing insufficient funds checks
- **Bypass fees**: `amount + fee` wraps, paying less than required

## Real-World Impact

Multiple token programs have been exploited through unchecked arithmetic. The Cashio stablecash protocol lost $52M in part due to arithmetic issues combined with other vulnerabilities. Any program handling balances, supplies, or fees without checked math is at risk.

## Vulnerable Code

```rust
pub fn mint_vulnerable(ctx: Context<Operate>, amount: u64) -> Result<()> {
    let ledger = &mut ctx.accounts.ledger;

    // VULNERABLE: wrapping addition
    // If total_supply = u64::MAX and amount = 1, result = 0
    ledger.total_supply = ledger.total_supply.wrapping_add(amount);
    ledger.user_balance = ledger.user_balance.wrapping_add(amount);

    Ok(())
}

pub fn burn_vulnerable(ctx: Context<Operate>, amount: u64) -> Result<()> {
    let ledger = &mut ctx.accounts.ledger;

    // VULNERABLE: wrapping subtraction
    // If user_balance = 10 and amount = 11, result = u64::MAX
    ledger.user_balance = ledger.user_balance.wrapping_sub(amount);

    Ok(())
}
```

## Secure Code

```rust
pub fn mint_secure(ctx: Context<Operate>, amount: u64) -> Result<()> {
    let ledger = &mut ctx.accounts.ledger;

    // SECURE: checked addition — returns error on overflow
    ledger.total_supply = ledger.total_supply
        .checked_add(amount)
        .ok_or(ErrorCode::ArithmeticOverflow)?;

    Ok(())
}

pub fn burn_secure(ctx: Context<Operate>, amount: u64) -> Result<()> {
    let ledger = &mut ctx.accounts.ledger;

    // SECURE: checked subtraction — returns error on underflow
    ledger.user_balance = ledger.user_balance
        .checked_sub(amount)
        .ok_or(ErrorCode::ArithmeticUnderflow)?;

    Ok(())
}
```

## The Fix

Use `checked_add()`, `checked_sub()`, `checked_mul()`, `checked_div()` instead of raw operators. These return `None` on overflow/underflow, which you convert to an error.

## Test It

```bash
# Build the program
cargo build-sbf --manifest-path patterns/03-integer-overflow/anchor/Cargo.toml

# Run exploit tests
SBF_OUT_DIR=target/deploy cargo test -p test-integer-overflow -- --nocapture
```

**What the tests prove:**
- `exploit_overflow_supply_wraps_to_zero` — Minting at `u64::MAX` wraps supply to 0
- `exploit_underflow_balance_wraps_to_max` — Burning more than balance wraps to `u64::MAX`
- `secure_blocks_overflow` — Secure mint rejects overflow (error 6000)
- `secure_blocks_underflow` — Secure burn rejects underflow (error 6001)
- `secure_allows_valid_mint` — Normal operations work fine

## Pinocchio Version

The vulnerability and fix are identical—checked arithmetic is standard Rust:

```rust
// VULNERABLE: wrapping arithmetic
fn mint_vulnerable(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let supply = u64::from_le_bytes(data[40..48].try_into()?);
    let new_supply = supply.wrapping_add(amount);  // Wraps at u64::MAX!
    data[40..48].copy_from_slice(&new_supply.to_le_bytes());
}

// SECURE: checked arithmetic
fn mint_secure(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let supply = u64::from_le_bytes(data[40..48].try_into()?);
    let new_supply = supply
        .checked_add(amount)
        .ok_or(ProgramError::Custom(ERR_OVERFLOW))?;
    data[40..48].copy_from_slice(&new_supply.to_le_bytes());
}
```

Build: `cargo build-sbf --manifest-path patterns/03-integer-overflow/pinocchio/Cargo.toml`

## Key Takeaway

**Never trust raw arithmetic with user-controlled values. `checked_*` methods exist for a reason—use them everywhere, Anchor or Pinocchio.**
