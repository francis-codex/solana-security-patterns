use anchor_lang::prelude::*;

declare_id!("8anCcUkKVms75R4HYTnkbM6YGzAra9WTmXhNEY5RSaNw");

/// # Missing Owner Check Vulnerability
///
/// ## Real-World Reference: Wormhole Bridge Hack ($326M, February 2022)
///
/// The Wormhole bridge was exploited because the program accepted a spoofed
/// "SignatureSet" account that was NOT owned by the Wormhole program. The
/// attacker created a fake account with data matching the expected layout,
/// bypassing all validation except ownership.
///
/// ## The Vulnerability
/// On Solana, any program can create accounts with arbitrary data. If your
/// program reads account data without verifying the account's `owner` field,
/// an attacker can craft a fake account with the right byte layout and pass
/// it in. Your program will deserialize it and trust the data.
///
/// ## Why This Matters
/// Anchor's `Account<'info, T>` type auto-checks owner == program_id.
/// Using raw `AccountInfo` or `UncheckedAccount` skips this check entirely.
#[program]
pub mod missing_owner {
    use super::*;

    /// Initialize a treasury account owned by this program.
    pub fn initialize(ctx: Context<Initialize>, amount: u64) -> Result<()> {
        let treasury = &mut ctx.accounts.treasury;
        treasury.authority = ctx.accounts.authority.key();
        treasury.balance = amount;
        treasury.is_active = true;
        msg!("Treasury initialized: authority={}, balance={}", treasury.authority, amount);
        Ok(())
    }

    // ============================================================================
    // VULNERABLE: Missing Owner Check
    // ============================================================================
    // ISSUE: The `treasury` account is passed as `AccountInfo` — Anchor does NOT
    //        verify that it is owned by THIS program. An attacker can:
    //        1. Create their own program that writes data matching Treasury layout
    //        2. Pass that fake account into this instruction
    //        3. The program reads it, trusts the data, and acts on it
    //
    // ATTACK SCENARIO (Wormhole-style):
    // 1. Attacker deploys a helper program that creates an account with:
    //    - authority = attacker's key
    //    - balance = 1_000_000 (fake balance)
    //    - is_active = true
    // 2. Attacker calls `process_vulnerable` with this fake account
    // 3. Program reads the fake data, trusts it, and grants access/funds
    //
    // ROOT CAUSE: The program trusts `AccountInfo` data without checking who owns it.
    // ============================================================================
    pub fn process_vulnerable(ctx: Context<ProcessVulnerable>) -> Result<()> {
        // VULNERABLE: Manually deserializing from raw AccountInfo.
        // No owner check — data could come from ANY program.
        let data = ctx.accounts.treasury.try_borrow_data()?;

        // Skip the 8-byte Anchor discriminator, then read fields
        let authority = Pubkey::try_from(&data[8..40]).map_err(|_| ErrorCode::InvalidData)?;
        let balance = u64::from_le_bytes(
            data[40..48].try_into().map_err(|_| ErrorCode::InvalidData)?,
        );
        let is_active = data[48] != 0;

        // The program trusts all of this — but it could be completely fake
        require!(is_active, ErrorCode::TreasuryInactive);

        msg!(
            "VULNERABLE: Processed treasury — authority={}, balance={} (UNVERIFIED OWNER!)",
            authority,
            balance
        );
        Ok(())
    }

    // ============================================================================
    // SECURE: Proper Owner Check
    // ============================================================================
    // FIX: The `treasury` account uses `Account<'info, Treasury>` type.
    //      Anchor automatically verifies:
    //      1. The account is owned by THIS program (owner == program_id)
    //      2. The 8-byte discriminator matches the Treasury type
    //      3. The data deserializes correctly into the Treasury struct
    //
    // WHY IT WORKS:
    // Even if an attacker creates a perfectly byte-matching account, the
    // owner field will be their program's ID, not ours. Anchor rejects it
    // before our code ever runs.
    //
    // DEFENSE IN DEPTH:
    // 1. `Account<'info, Treasury>` — auto owner check + discriminator check
    // 2. `has_one = authority` — ensures the stored authority matches
    // Both prevent the Wormhole-style attack.
    // ============================================================================
    pub fn process_secure(ctx: Context<ProcessSecure>) -> Result<()> {
        let treasury = &ctx.accounts.treasury;

        require!(treasury.is_active, ErrorCode::TreasuryInactive);

        msg!(
            "SECURE: Processed treasury — authority={}, balance={} (OWNER VERIFIED)",
            treasury.authority,
            treasury.balance
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
        space = 8 + Treasury::INIT_SPACE,
    )]
    pub treasury: Account<'info, Treasury>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

/// VULNERABLE: treasury is a raw AccountInfo — no owner verification
#[derive(Accounts)]
pub struct ProcessVulnerable<'info> {
    /// CHECK: VULNERABLE — This is raw AccountInfo with no owner check!
    /// An attacker can pass an account owned by ANY program.
    /// The `has_one` constraint CANNOT be used here because AccountInfo
    /// doesn't have typed fields to compare against.
    pub treasury: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

/// SECURE: treasury is Account<Treasury> — Anchor auto-checks owner
#[derive(Accounts)]
pub struct ProcessSecure<'info> {
    // Account<'info, Treasury> guarantees:
    // 1. Owner is this program
    // 2. Discriminator matches Treasury
    // 3. Data deserializes correctly
    #[account(has_one = authority)]
    pub treasury: Account<'info, Treasury>,
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Treasury {
    pub authority: Pubkey, // 32 bytes
    pub balance: u64,      // 8 bytes
    pub is_active: bool,   // 1 byte
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid account data")]
    InvalidData,
    #[msg("Treasury is not active")]
    TreasuryInactive,
}
