use anchor_lang::prelude::*;

declare_id!("3w5jyYEgbsnHjFcTUH9xdyH3KfN2YRppPCFUkskyYSxA");

/// # Integer Overflow/Underflow Vulnerability
///
/// ## The Vulnerability
/// Rust's release builds wrap on overflow by default. On Solana, BPF programs
/// compile in release mode, so `a + b` silently wraps around instead of
/// panicking. An attacker exploits this to:
/// - Underflow a balance check: `balance - withdraw_amount` wraps to u64::MAX
/// - Overflow a mint: `supply + mint_amount` wraps to a small number
/// - Bypass fee calculations: `amount + fee` wraps, paying less than required
///
/// ## Real-World Impact
/// Multiple token programs have been exploited through unchecked arithmetic,
/// allowing infinite minting or bypassing balance validations.
///
/// ## Note on Anchor
/// Anchor 0.31+ enables `overflow-checks = true` in release profiles by default
/// via Cargo.toml. However, if a developer manually disables this, or uses
/// wrapped arithmetic in raw Rust, the vulnerability exists. This pattern
/// teaches WHY checked math matters, regardless of framework defaults.
#[program]
pub mod integer_overflow {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, initial_supply: u64) -> Result<()> {
        let ledger = &mut ctx.accounts.ledger;
        ledger.authority = ctx.accounts.authority.key();
        ledger.total_supply = initial_supply;
        ledger.user_balance = 0;
        msg!("Ledger initialized: supply={}", initial_supply);
        Ok(())
    }

    // ============================================================================
    // VULNERABLE: Unchecked Arithmetic
    // ============================================================================
    // ISSUE: Uses wrapping arithmetic. On Solana BPF (release mode), u64
    //        operations wrap silently. An attacker can:
    //
    //   1. OVERFLOW the supply:
    //      supply = u64::MAX, mint_amount = 1
    //      supply + mint_amount = 0 (wrapped!)
    //      The attacker mints tokens while the supply resets to zero.
    //
    //   2. UNDERFLOW a balance:
    //      balance = 10, withdraw = 11
    //      balance - withdraw = u64::MAX (wrapped!)
    //      The attacker bypasses the "insufficient funds" check.
    //
    // NOTE: We use .wrapping_add / .wrapping_sub to simulate what happens
    //       when overflow-checks are disabled (the real-world scenario).
    // ============================================================================
    pub fn mint_vulnerable(ctx: Context<Operate>, amount: u64) -> Result<()> {
        let ledger = &mut ctx.accounts.ledger;

        // VULNERABLE: wrapping addition — supply can overflow to zero
        ledger.total_supply = ledger.total_supply.wrapping_add(amount);
        ledger.user_balance = ledger.user_balance.wrapping_add(amount);

        msg!(
            "VULNERABLE MINT: amount={}, new_supply={}, new_balance={}",
            amount,
            ledger.total_supply,
            ledger.user_balance
        );
        Ok(())
    }

    pub fn burn_vulnerable(ctx: Context<Operate>, amount: u64) -> Result<()> {
        let ledger = &mut ctx.accounts.ledger;

        // VULNERABLE: wrapping subtraction — balance can underflow to u64::MAX
        ledger.user_balance = ledger.user_balance.wrapping_sub(amount);
        ledger.total_supply = ledger.total_supply.wrapping_sub(amount);

        msg!(
            "VULNERABLE BURN: amount={}, new_supply={}, new_balance={}",
            amount,
            ledger.total_supply,
            ledger.user_balance
        );
        Ok(())
    }

    // ============================================================================
    // SECURE: Checked Arithmetic
    // ============================================================================
    // FIX: Uses checked_add / checked_sub which return None on overflow/underflow.
    //      The program explicitly handles the error case.
    //
    // WHY THIS WORKS:
    // - checked_add(amount) returns None if result > u64::MAX
    // - checked_sub(amount) returns None if result < 0
    // - .ok_or() converts None into a program error
    //
    // BEST PRACTICE:
    // Always use checked math for any arithmetic involving user-supplied values
    // or values that could theoretically overflow (balances, supplies, fees).
    // ============================================================================
    pub fn mint_secure(ctx: Context<Operate>, amount: u64) -> Result<()> {
        let ledger = &mut ctx.accounts.ledger;

        // SECURE: checked addition — returns error on overflow
        ledger.total_supply = ledger
            .total_supply
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;

        ledger.user_balance = ledger
            .user_balance
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;

        msg!(
            "SECURE MINT: amount={}, new_supply={}, new_balance={}",
            amount,
            ledger.total_supply,
            ledger.user_balance
        );
        Ok(())
    }

    pub fn burn_secure(ctx: Context<Operate>, amount: u64) -> Result<()> {
        let ledger = &mut ctx.accounts.ledger;

        // SECURE: checked subtraction — returns error on underflow
        ledger.user_balance = ledger
            .user_balance
            .checked_sub(amount)
            .ok_or(ErrorCode::ArithmeticUnderflow)?;

        ledger.total_supply = ledger
            .total_supply
            .checked_sub(amount)
            .ok_or(ErrorCode::ArithmeticUnderflow)?;

        msg!(
            "SECURE BURN: amount={}, new_supply={}, new_balance={}",
            amount,
            ledger.total_supply,
            ledger.user_balance
        );
        Ok(())
    }
}

// ============================================================================
// Account Structures
// ============================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Ledger::INIT_SPACE,
    )]
    pub ledger: Account<'info, Ledger>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Operate<'info> {
    #[account(mut, has_one = authority)]
    pub ledger: Account<'info, Ledger>,
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Ledger {
    pub authority: Pubkey,    // 32 bytes
    pub total_supply: u64,    // 8 bytes
    pub user_balance: u64,    // 8 bytes
}

#[error_code]
pub enum ErrorCode {
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
    #[msg("Arithmetic underflow")]
    ArithmeticUnderflow,
}
