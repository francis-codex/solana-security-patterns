use anchor_lang::prelude::*;

declare_id!("x1rqubJg3BK9Q5FbHqaxSW4cU5toBeAQkWyw8cELaRm");

/// # PDA Bump Seed Canonicalization
///
/// ## The Vulnerability
/// `Pubkey::create_program_address` accepts any valid bump (0-255) that
/// produces an off-curve point. `Pubkey::find_program_address` finds the
/// HIGHEST valid bump (the "canonical" bump). If a program accepts a
/// user-supplied bump without enforcing the canonical one, an attacker can
/// use a different valid bump to create a separate PDA that maps to different
/// state — enabling duplicate accounts, DoS, or fund theft.
///
/// ## Why It Matters
/// Multiple valid bumps can exist for the same seeds. If the program stores
/// data at a user-chosen bump, an attacker can create entries at non-canonical
/// bumps to bypass uniqueness constraints or confuse lookups.
///
/// ## Anchor's Protection
/// Anchor's `seeds` + `bump` constraint auto-derives and verifies the
/// canonical bump. You'd have to deliberately bypass this to be vulnerable.
#[program]
pub mod pda_bump {
    use super::*;

    // ============================================================================
    // VULNERABLE: Accepts any user-supplied bump
    // ============================================================================
    // ISSUE: The program accepts `bump` as an instruction argument and uses it
    //        directly in `create_program_address`. An attacker can:
    //
    //   1. Find the canonical bump (e.g., 253) — this is what the legitimate user uses
    //   2. Grind for another valid bump (e.g., 251) for the same seeds
    //   3. Create a separate account at bump=251 with different data
    //   4. The program treats both as valid, breaking uniqueness assumptions
    //
    // EXAMPLE ATTACK:
    // - Legitimate: PDA(seeds=["vault", user], bump=253) → balance = 100
    // - Attacker:   PDA(seeds=["vault", user], bump=251) → balance = 999999
    // ============================================================================
    pub fn set_value_vulnerable(
        ctx: Context<SetValueVulnerable>,
        bump: u8,
        value: u64,
    ) -> Result<()> {
        // VULNERABLE: Uses caller-supplied bump without validation
        let seeds = &[b"data" as &[u8], ctx.accounts.user.key.as_ref(), &[bump]];

        let pda = Pubkey::create_program_address(seeds, ctx.program_id)
            .map_err(|_| ErrorCode::InvalidBump)?;

        // Verify the derived PDA matches the provided account
        require_keys_eq!(pda, ctx.accounts.data_account.key(), ErrorCode::PdaMismatch);

        let data_account = &mut ctx.accounts.data_account;
        data_account.user = ctx.accounts.user.key();
        data_account.value = value;
        data_account.bump = bump; // Stores whatever bump was provided

        msg!(
            "VULNERABLE: Set value={} at bump={} (non-canonical bump accepted!)",
            value,
            bump
        );
        Ok(())
    }

    // ============================================================================
    // SECURE: Enforces canonical bump
    // ============================================================================
    // FIX: Use `find_program_address` to derive the canonical bump and reject
    //      any other bump value. This guarantees a single unique PDA per seed set.
    //
    // ALTERNATIVE (Anchor-idiomatic):
    // Use `#[account(seeds = [...], bump)]` — Anchor auto-derives and verifies
    // the canonical bump. We show the manual approach for educational clarity.
    // ============================================================================
    pub fn set_value_secure(
        ctx: Context<SetValueSecure>,
        value: u64,
    ) -> Result<()> {
        // SECURE: Derive canonical bump — always the highest valid bump
        let (expected_pda, canonical_bump) = Pubkey::find_program_address(
            &[b"data", ctx.accounts.user.key.as_ref()],
            ctx.program_id,
        );

        require_keys_eq!(
            expected_pda,
            ctx.accounts.data_account.key(),
            ErrorCode::PdaMismatch
        );

        let data_account = &mut ctx.accounts.data_account;
        data_account.user = ctx.accounts.user.key();
        data_account.value = value;
        data_account.bump = canonical_bump; // Always stores canonical bump

        msg!(
            "SECURE: Set value={} at canonical bump={} (only valid bump accepted)",
            value,
            canonical_bump
        );
        Ok(())
    }
}

// ============================================================================
// Account Structures
// ============================================================================

#[derive(Accounts)]
pub struct SetValueVulnerable<'info> {
    #[account(mut)]
    pub data_account: Account<'info, DataAccount>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetValueSecure<'info> {
    #[account(mut)]
    pub data_account: Account<'info, DataAccount>,
    pub user: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct DataAccount {
    pub user: Pubkey,  // 32 bytes
    pub value: u64,    // 8 bytes
    pub bump: u8,      // 1 byte
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid bump seed")]
    InvalidBump,
    #[msg("PDA address mismatch")]
    PdaMismatch,
}
