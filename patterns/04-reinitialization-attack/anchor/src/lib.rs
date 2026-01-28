use anchor_lang::prelude::*;

declare_id!("2P1GgtagVaYR8B6FhrPHdP4Mmy3pUFAZtSyeWFK293vg");

/// # Re-initialization Attack
///
/// ## The Vulnerability
/// If an account can be initialized more than once, an attacker can reset
/// its state. This lets them:
/// - Replace the authority with their own key (seize control)
/// - Reset balances (steal deposited funds)
/// - Clear security flags (bypass checks)
///
/// ## Real-World Impact
/// Multiple DeFi protocols have been exploited when config/vault accounts
/// could be re-initialized, allowing attackers to take ownership.
///
/// ## Anchor Context
/// Anchor's `init` constraint is safe — it only works on uninitialized
/// accounts. But `init_if_needed` is dangerous if misused, and raw
/// AccountInfo-based initialization has no built-in protection.
#[program]
pub mod reinitialization {
    use super::*;

    // ============================================================================
    // VULNERABLE: No initialization guard
    // ============================================================================
    // ISSUE: This instruction writes config data without checking if the
    //        account was already initialized. An attacker can:
    //
    //   1. Wait for the legitimate owner to initialize the config
    //   2. Call init_vulnerable again with their own key as authority
    //   3. The config is overwritten — attacker now controls the account
    //
    // WHY IT WORKS:
    // The instruction blindly writes to the account data without checking
    // the `is_initialized` flag. There's no guard preventing re-invocation.
    // ============================================================================
    pub fn init_vulnerable(ctx: Context<InitVulnerable>) -> Result<()> {
        let config = &mut ctx.accounts.config;

        // VULNERABLE: No check for existing initialization.
        // An attacker can overwrite the authority at any time.
        config.authority = ctx.accounts.authority.key();
        config.is_initialized = true;
        config.vault_balance = 0;

        msg!(
            "VULNERABLE INIT: authority set to {} (no re-init guard!)",
            config.authority
        );
        Ok(())
    }

    // ============================================================================
    // SECURE: Initialization guard
    // ============================================================================
    // FIX: Check `is_initialized` before writing. If already true, reject.
    //
    // ALTERNATIVE FIXES:
    // 1. Use Anchor's `init` constraint (only works on empty accounts)
    // 2. Use a PDA with fixed seeds (can only be created once)
    // 3. Check the discriminator (Anchor sets it during init)
    //
    // We show the manual check here for educational clarity, then also
    // provide the Anchor `init` version.
    // ============================================================================
    pub fn init_secure(ctx: Context<InitSecure>) -> Result<()> {
        let config = &mut ctx.accounts.config;

        // SECURE: Reject if already initialized
        require!(!config.is_initialized, ErrorCode::AlreadyInitialized);

        config.authority = ctx.accounts.authority.key();
        config.is_initialized = true;
        config.vault_balance = 0;

        msg!(
            "SECURE INIT: authority set to {} (one-time only)",
            config.authority
        );
        Ok(())
    }

    /// Anchor's `init` constraint version — the framework-idiomatic approach.
    /// The `init` constraint ensures the account is brand new (zero lamports,
    /// no data). It can never be called twice on the same account.
    pub fn init_anchor_native(ctx: Context<InitAnchorNative>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.authority = ctx.accounts.authority.key();
        config.is_initialized = true;
        config.vault_balance = 0;

        msg!(
            "ANCHOR INIT: authority set to {} (init constraint enforced)",
            config.authority
        );
        Ok(())
    }
}

// ============================================================================
// Account Structures
// ============================================================================

/// VULNERABLE: Config is mutable — anyone can call init again
#[derive(Accounts)]
pub struct InitVulnerable<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    pub authority: Signer<'info>,
}

/// SECURE: Manual is_initialized check in instruction logic
#[derive(Accounts)]
pub struct InitSecure<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    pub authority: Signer<'info>,
}

/// SECURE (Anchor-native): Uses `init` constraint — one-time only
#[derive(Accounts)]
pub struct InitAnchorNative<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Config::INIT_SPACE,
    )]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub authority: Pubkey,    // 32 bytes
    pub is_initialized: bool, // 1 byte
    pub vault_balance: u64,   // 8 bytes
}

#[error_code]
pub enum ErrorCode {
    #[msg("Account already initialized")]
    AlreadyInitialized,
}
