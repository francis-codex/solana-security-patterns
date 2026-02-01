//! # Pattern 5: PDA Bump Seed Canonicalization (Pinocchio)
//!
//! Demonstrates accepting non-canonical bumps, allowing duplicate PDAs.

#![no_std]

pinocchio::nostd_panic_handler!();

use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    msg,
    program_error::ProgramError,
    pubkey::{create_program_address, find_program_address, Pubkey},
    ProgramResult,
};

entrypoint!(process_instruction);

const IX_SET_VALUE_VULNERABLE: u8 = 0;
const IX_SET_VALUE_SECURE: u8 = 1;

const ERR_INVALID_BUMP: u32 = 5001;
const ERR_PDA_MISMATCH: u32 = 5002;

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = instruction_data
        .first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *instruction {
        IX_SET_VALUE_VULNERABLE => set_value_vulnerable(program_id, accounts, instruction_data),
        IX_SET_VALUE_SECURE => set_value_secure(program_id, accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ============================================================================
// VULNERABLE: Accepts user-supplied bump
// ============================================================================
// ISSUE: The program accepts `bump` as an instruction argument and uses it
//        directly. Multiple valid bumps can exist for the same seeds.
//
// ATTACK:
//   1. Legitimate user creates PDA with canonical bump (e.g., 253)
//   2. Attacker finds another valid bump (e.g., 251) for same seeds
//   3. Attacker creates account at non-canonical PDA
//   4. Program now has TWO accounts for same logical entity
//   5. Attacker manipulates the shadow account
//
// find_program_address returns the HIGHEST valid bump (canonical).
// create_program_address accepts ANY valid bump.
// ============================================================================
fn set_value_vulnerable(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let data_account = &accounts[0];
    let user = &accounts[1];

    // Parse bump from instruction data (byte 1)
    let bump = instruction_data[1];

    // Parse value from instruction data (bytes 2-9)
    let value = u64::from_le_bytes(
        instruction_data[2..10]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // VULNERABLE: Uses caller-supplied bump without validation
    // Attacker can use any valid bump, not just the canonical one
    let seeds: &[&[u8]] = &[b"data", user.key().as_ref(), &[bump]];

    let expected_pda = create_program_address(seeds, program_id)
        .map_err(|_| ProgramError::Custom(ERR_INVALID_BUMP))?;

    if expected_pda != *data_account.key() {
        return Err(ProgramError::Custom(ERR_PDA_MISMATCH));
    }

    // Write data
    let mut data = data_account.try_borrow_mut_data()?;
    data[8..40].copy_from_slice(user.key().as_ref());
    data[40..48].copy_from_slice(&value.to_le_bytes());
    data[48] = bump; // Stores whatever bump was provided

    msg!("VULNERABLE: Value set at user-supplied bump");
    Ok(())
}

// ============================================================================
// SECURE: Derives canonical bump internally
// ============================================================================
// FIX: Use find_program_address to derive the canonical bump (highest valid).
// Reject any PDA that doesn't match the canonical derivation.
//
// This guarantees one PDA per seed set.
// ============================================================================
fn set_value_secure(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let data_account = &accounts[0];
    let user = &accounts[1];

    let value = u64::from_le_bytes(
        instruction_data[1..9]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // SECURE: Derive canonical bump (highest valid bump)
    let seeds: &[&[u8]] = &[b"data", user.key().as_ref()];
    let (expected_pda, canonical_bump) = find_program_address(seeds, program_id);

    if expected_pda != *data_account.key() {
        msg!("ERROR: PDA does not match canonical derivation");
        return Err(ProgramError::Custom(ERR_PDA_MISMATCH));
    }

    // Write data with canonical bump
    let mut data = data_account.try_borrow_mut_data()?;
    data[8..40].copy_from_slice(user.key().as_ref());
    data[40..48].copy_from_slice(&value.to_le_bytes());
    data[48] = canonical_bump; // Always stores canonical bump

    msg!("SECURE: Value set at canonical bump only");
    Ok(())
}
