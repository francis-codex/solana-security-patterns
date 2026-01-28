use anchor_lang::prelude::*;

declare_id!("HF33f3iZYeK7qz7AE1aWWGvQuxArTudNjKVseAhTYCRC");

/// # Missing Signer Check Vulnerability
///
/// This program demonstrates one of the most common security vulnerabilities in Solana:
/// failing to verify that an account has actually signed the transaction.
///
/// ## The Vulnerability
/// When a program expects an authority to authorize an action but doesn't verify
/// the signature, anyone can pass any pubkey as the "authority" and the instruction
/// will succeed even though that authority never approved the transaction.
///
/// ## Real-World Impact
/// This vulnerability has led to millions in losses across DeFi protocols.
/// An attacker can drain funds, modify state, or perform privileged operations
/// by simply passing the victim's public key without needing their private key.
#[program]
pub mod missing_signer {
    use super::*;

    /// Initialize a new vault with an authority who can withdraw funds
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        msg!("Vault initialized with authority: {}", vault.authority);
        Ok(())
    }

    /// Deposit lamports into the vault
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        // Transfer lamports from depositor to vault
        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &ctx.accounts.depositor.key(),
            &ctx.accounts.vault.key(),
            amount,
        );
        anchor_lang::solana_program::program::invoke(
            &ix,
            &[
                ctx.accounts.depositor.to_account_info(),
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_add(amount).ok_or(ErrorCode::Overflow)?;
        msg!("Deposited {} lamports. New balance: {}", amount, vault.balance);
        Ok(())
    }

    // ============================================================================
    // VULNERABLE: Missing Signer Verification
    // ============================================================================
    // ISSUE: The `authority` account is NOT verified as a signer. Anyone can pass
    //        any pubkey as the authority - the instruction will succeed even if
    //        that key never signed the transaction.
    //
    // ATTACK SCENARIO:
    // 1. Attacker sees a vault with 100 SOL, authority = Alice's pubkey
    // 2. Attacker calls withdraw_vulnerable, passing:
    //    - vault: the target vault
    //    - authority: Alice's pubkey (NOT signing)
    //    - recipient: Attacker's account
    // 3. Transaction succeeds - attacker steals all funds
    //
    // WHY IT WORKS:
    // Anchor's `AccountInfo` type only ensures the account exists in the transaction.
    // It does NOT verify signatures. The `has_one = authority` constraint only checks
    // that the authority field MATCHES the provided account - not that it signed.
    // ============================================================================
    pub fn withdraw_vulnerable(ctx: Context<WithdrawVulnerable>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // This check passes even without a signature!
        // has_one only verifies: vault.authority == authority.key()
        require!(vault.balance >= amount, ErrorCode::InsufficientFunds);

        vault.balance = vault.balance.checked_sub(amount).ok_or(ErrorCode::Underflow)?;

        // Transfer lamports (would actually drain the vault in real code)
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.recipient.try_borrow_mut_lamports()? += amount;

        msg!("VULNERABLE: Withdrew {} lamports without signature verification!", amount);
        Ok(())
    }

    // ============================================================================
    // SECURE: Proper Signer Verification
    // ============================================================================
    // FIX: The `authority` account is declared as `Signer<'info>` type.
    //      Anchor automatically verifies that this account signed the transaction.
    //      If the signature is missing, the transaction fails BEFORE our code runs.
    //
    // SECURITY GUARANTEE:
    // - The authority MUST possess the private key to sign
    // - No one can impersonate the authority without the private key
    // - The `has_one` constraint ensures it's the CORRECT authority for this vault
    //
    // DEFENSE IN DEPTH:
    // 1. `Signer<'info>` - Verifies signature exists
    // 2. `has_one = authority` - Verifies it's the vault's designated authority
    // Both checks are required for complete security.
    // ============================================================================
    pub fn withdraw_secure(ctx: Context<WithdrawSecure>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        require!(vault.balance >= amount, ErrorCode::InsufficientFunds);

        vault.balance = vault.balance.checked_sub(amount).ok_or(ErrorCode::Underflow)?;

        // Transfer lamports
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.recipient.try_borrow_mut_lamports()? += amount;

        msg!("SECURE: Withdrew {} lamports with proper signature verification", amount);
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
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub depositor: Signer<'info>,
    pub system_program: Program<'info, System>,
}

/// VULNERABLE account structure - authority is NOT a Signer
#[derive(Accounts)]
pub struct WithdrawVulnerable<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump,
        has_one = authority  // Only checks pubkey match, NOT signature!
    )]
    pub vault: Account<'info, Vault>,

    /// CHECK: VULNERABLE - This is an AccountInfo, not a Signer!
    /// Anyone can pass any pubkey here without proving ownership.
    /// The `has_one` constraint above only verifies the pubkey matches,
    /// it does NOT verify the account actually signed the transaction.
    pub authority: AccountInfo<'info>,

    /// CHECK: Recipient to receive withdrawn funds
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}

/// SECURE account structure - authority IS a Signer
#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump,
        has_one = authority  // Pubkey match
    )]
    pub vault: Account<'info, Vault>,

    // SECURE: Using Signer type guarantees the transaction was signed
    // by the private key corresponding to this public key.
    // If signature is missing, Anchor rejects the transaction immediately.
    pub authority: Signer<'info>,

    /// CHECK: Recipient to receive withdrawn funds
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Arithmetic underflow")]
    Underflow,
}
