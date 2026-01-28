use anchor_lang::prelude::*;

declare_id!("HS241bzcteDvCTi6UMEfecj3o8JieRvZVL3F1zhZGPxP");

/// # Type Cosplay (Account Confusion)
///
/// ## The Vulnerability
/// When a program uses raw `AccountInfo` (or `UncheckedAccount`) and manually
/// reads fields at fixed byte offsets WITHOUT verifying the 8-byte Anchor
/// discriminator, an attacker can pass an account of a DIFFERENT type that
/// has the same binary layout. The program treats the wrong type as the
/// expected type — a "type cosplay."
///
/// ## Why It Matters
/// If `AdminConfig` stores `admin: Pubkey` at offset 8 and `UserData` stores
/// `authority: Pubkey` at the same offset, an attacker can:
///   1. Legitimately create a `UserData` with `authority = attacker_key`
///   2. Pass it where `AdminConfig` is expected
///   3. The program reads `attacker_key` as the "admin" — unauthorized access
///
/// ## Anchor's Protection
/// `Account<'info, T>` automatically verifies the first 8 bytes match the
/// expected discriminator (`sha256("account:{TypeName}")[..8]`). Different
/// types produce different discriminators, making cosplay impossible.
#[program]
pub mod type_cosplay {
    use super::*;

    // ============================================================================
    // VULNERABLE: Uses UncheckedAccount — no discriminator verification
    // ============================================================================
    // ISSUE: The program reads fields at fixed byte offsets from a raw
    //        AccountInfo without checking the 8-byte discriminator prefix.
    //        Any account with a Pubkey at offset 8 can masquerade as AdminConfig.
    //
    // ATTACK SCENARIO:
    //   1. Program has AdminConfig { admin: Pubkey, fee_basis_points: u64 }
    //   2. Program also has UserData { authority: Pubkey, balance: u64 }
    //   3. Both have identical layouts after their (different) discriminators
    //   4. Attacker creates UserData with authority = attacker_key
    //   5. Passes UserData account to update_fee_vulnerable
    //   6. Program reads attacker_key at offset 8, thinks it's the admin
    //   7. Attacker updates fees without being the real admin
    // ============================================================================
    pub fn update_fee_vulnerable(
        ctx: Context<UpdateFeeVulnerable>,
        new_fee: u64,
    ) -> Result<()> {
        let data = ctx.accounts.config.try_borrow_data()?;

        // VULNERABLE: Reads the Pubkey at offset 8 (after discriminator)
        // but NEVER checks what the discriminator actually is.
        // A UserData account has a different discriminator but the same
        // field layout — the authority Pubkey sits at the exact same offset.
        let admin_bytes: [u8; 32] = data[8..40]
            .try_into()
            .map_err(|_| ErrorCode::DeserializationFailed)?;
        let admin = Pubkey::from(admin_bytes);

        // Check that the signer matches the "admin" field
        // But if this is actually a UserData account, we just read the
        // attacker's authority key — so this check passes for the attacker!
        require_keys_eq!(admin, ctx.accounts.authority.key(), ErrorCode::Unauthorized);

        drop(data);

        // Write the new fee at offset 40 (after discriminator + Pubkey)
        let mut data = ctx.accounts.config.try_borrow_mut_data()?;
        data[40..48].copy_from_slice(&new_fee.to_le_bytes());

        msg!(
            "VULNERABLE: Fee updated to {} (no discriminator check!)",
            new_fee
        );
        Ok(())
    }

    // ============================================================================
    // SECURE: Uses Account<AdminConfig> — discriminator auto-verified
    // ============================================================================
    // FIX: Anchor's `Account<'info, AdminConfig>` deserializes the account and
    //      verifies its 8-byte discriminator matches `sha256("account:AdminConfig")`.
    //      A UserData account has discriminator `sha256("account:UserData")` which
    //      is completely different — Anchor rejects it immediately.
    // ============================================================================
    pub fn update_fee_secure(
        ctx: Context<UpdateFeeSecure>,
        new_fee: u64,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;

        // SECURE: Anchor already verified the discriminator matches AdminConfig.
        // A UserData account would be rejected before we even reach this code.
        require_keys_eq!(
            config.admin,
            ctx.accounts.authority.key(),
            ErrorCode::Unauthorized
        );

        config.fee_basis_points = new_fee;

        msg!(
            "SECURE: Fee updated to {} (discriminator verified)",
            new_fee
        );
        Ok(())
    }
}

// ============================================================================
// Account Structures
// ============================================================================
//
// KEY INSIGHT: Both types have identical binary layouts after their
// discriminators: [Pubkey (32 bytes)][u64 (8 bytes)]
//
// But their discriminators are different:
//   AdminConfig → sha256("account:AdminConfig")[..8]
//   UserData    → sha256("account:UserData")[..8]
//
// Without checking the discriminator, the program can't tell them apart.

#[derive(Accounts)]
pub struct UpdateFeeVulnerable<'info> {
    /// CHECK: Deliberately unchecked — demonstrates type cosplay vulnerability.
    /// No discriminator or owner verification is performed.
    #[account(mut)]
    pub config: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateFeeSecure<'info> {
    #[account(mut)]
    pub config: Account<'info, AdminConfig>,
    pub authority: Signer<'info>,
}

/// Admin configuration — the REAL account type for fee management.
#[account]
#[derive(InitSpace)]
pub struct AdminConfig {
    pub admin: Pubkey,         // 32 bytes — the authorized admin
    pub fee_basis_points: u64, //  8 bytes — fee in basis points
}

/// User data — a DIFFERENT account type with the same field layout.
/// An attacker can create this with their key and pass it as AdminConfig.
#[account]
#[derive(InitSpace)]
pub struct UserData {
    pub authority: Pubkey, // 32 bytes — same offset as admin!
    pub balance: u64,      //  8 bytes — same offset as fee_basis_points!
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized: signer is not admin")]
    Unauthorized,
    #[msg("Failed to deserialize account data")]
    DeserializationFailed,
}
