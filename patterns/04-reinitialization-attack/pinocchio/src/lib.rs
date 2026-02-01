//! # Pattern 4: Re-initialization Attack (Pinocchio)
//!
//! Demonstrates allowing accounts to be initialized multiple times,
//! enabling attackers to overwrite authority and steal funds.

#![no_std]

pinocchio::nostd_panic_handler!();

use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

entrypoint!(process_instruction);

const IX_INIT_VULNERABLE: u8 = 0;
const IX_INIT_SECURE: u8 = 1;

const ERR_ALREADY_INITIALIZED: u32 = 4001;

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = instruction_data
        .first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *instruction {
        IX_INIT_VULNERABLE => init_vulnerable(accounts),
        IX_INIT_SECURE => init_secure(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ============================================================================
// VULNERABLE: No initialization guard
// ============================================================================
// ISSUE: This instruction writes config data without checking if the account
//        was already initialized. An attacker can:
//
//   1. Wait for legitimate owner to initialize config
//   2. Call init_vulnerable again with attacker's key as authority
//   3. Config is overwritten - attacker now controls the account
//
// ATTACK SCENARIO:
//   - Alice creates config with authority = Alice
//   - Alice deposits 1000 SOL to associated vault
//   - Attacker calls init_vulnerable with authority = Attacker
//   - Config now has authority = Attacker
//   - Attacker withdraws all funds
// ============================================================================
fn init_vulnerable(accounts: &[AccountInfo]) -> ProgramResult {
    let config = &accounts[0];
    let authority = &accounts[1];

    let mut data = config.try_borrow_mut_data()?;

    // VULNERABLE: No check for existing initialization!
    // Just blindly write the new authority.

    // Write discriminator (8 bytes)
    data[0..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

    // Write authority pubkey (32 bytes at offset 8)
    data[8..40].copy_from_slice(authority.key().as_ref());

    // Write is_initialized = true (1 byte at offset 40)
    data[40] = 1;

    // Write vault_balance = 0 (8 bytes at offset 41)
    data[41..49].copy_from_slice(&0u64.to_le_bytes());

    msg!("VULNERABLE INIT: Authority overwritten without check");
    Ok(())
}

// ============================================================================
// SECURE: Checks is_initialized before writing
// ============================================================================
// FIX: Check the is_initialized flag before writing. If already true, reject.
//
// This ensures initialization is a one-time operation.
// ============================================================================
fn init_secure(accounts: &[AccountInfo]) -> ProgramResult {
    let config = &accounts[0];
    let authority = &accounts[1];

    let mut data = config.try_borrow_mut_data()?;

    // SECURE: Check if already initialized
    let is_initialized = data[40] != 0;

    if is_initialized {
        msg!("ERROR: Config already initialized");
        return Err(ProgramError::Custom(ERR_ALREADY_INITIALIZED));
    }

    // Safe to initialize - first time only
    data[0..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    data[8..40].copy_from_slice(authority.key().as_ref());
    data[40] = 1; // is_initialized = true
    data[41..49].copy_from_slice(&0u64.to_le_bytes());

    msg!("SECURE INIT: Authority set (one-time only)");
    Ok(())
}
