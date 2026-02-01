//! # Pattern 6: Type Cosplay (Pinocchio)
//!
//! Demonstrates passing wrong account type with same binary layout.

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

const IX_UPDATE_FEE_VULNERABLE: u8 = 0;
const IX_UPDATE_FEE_SECURE: u8 = 1;

const ERR_UNAUTHORIZED: u32 = 6001;
const ERR_WRONG_DISCRIMINATOR: u32 = 6002;

// Discriminators (first 8 bytes) to distinguish account types
const ADMIN_CONFIG_DISCRIMINATOR: [u8; 8] = [0xAD, 0x11, 0x1C, 0x0F, 0x19, 0x00, 0x00, 0x01];
const USER_DATA_DISCRIMINATOR: [u8; 8] = [0x05, 0xE7, 0xDA, 0x7A, 0x00, 0x00, 0x00, 0x02];

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = instruction_data
        .first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    let new_fee = u64::from_le_bytes(
        instruction_data[1..9]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    match *instruction {
        IX_UPDATE_FEE_VULNERABLE => update_fee_vulnerable(accounts, new_fee),
        IX_UPDATE_FEE_SECURE => update_fee_secure(accounts, new_fee),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ============================================================================
// VULNERABLE: Does NOT check account discriminator
// ============================================================================
// ISSUE: We read fields at fixed byte offsets without verifying the account
//        type via its discriminator. Two different types with same layout:
//
//   AdminConfig: [8-byte disc][admin: Pubkey][fee: u64]
//   UserData:    [8-byte disc][authority: Pubkey][balance: u64]
//
// Both have a Pubkey at offset 8. If we only read offset 8 without checking
// the discriminator, a UserData account looks like an AdminConfig.
//
// ATTACK:
//   1. Attacker creates UserData with authority = attacker's key
//   2. Passes UserData to update_fee_vulnerable (expects AdminConfig)
//   3. Program reads attacker's key at offset 8 as "admin"
//   4. Attacker passes admin check and modifies fees
// ============================================================================
fn update_fee_vulnerable(accounts: &[AccountInfo], new_fee: u64) -> ProgramResult {
    let config = &accounts[0];
    let authority = &accounts[1];

    let data = config.try_borrow_data()?;

    // VULNERABLE: Reading "admin" at offset 8 without checking discriminator!
    // This could be a UserData account where offset 8 is "authority", not "admin"
    let admin = read_pubkey(&data[8..40]);

    if admin != *authority.key() {
        return Err(ProgramError::Custom(ERR_UNAUTHORIZED));
    }

    if !authority.is_signer() {
        return Err(ProgramError::Custom(ERR_UNAUTHORIZED));
    }

    drop(data);

    // Write new fee at offset 40
    let mut data = config.try_borrow_mut_data()?;
    data[40..48].copy_from_slice(&new_fee.to_le_bytes());

    msg!("VULNERABLE: Fee updated without type check");
    Ok(())
}

// ============================================================================
// SECURE: Checks discriminator before trusting data
// ============================================================================
// FIX: Verify the 8-byte discriminator matches the expected account type.
// This is what Anchor's Account<T> does automatically.
//
// Different types have different discriminators:
//   AdminConfig: sha256("account:AdminConfig")[..8]
//   UserData: sha256("account:UserData")[..8]
// ============================================================================
fn update_fee_secure(accounts: &[AccountInfo], new_fee: u64) -> ProgramResult {
    let config = &accounts[0];
    let authority = &accounts[1];

    let data = config.try_borrow_data()?;

    // SECURE: Check discriminator FIRST
    let discriminator: [u8; 8] = data[0..8]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    if discriminator != ADMIN_CONFIG_DISCRIMINATOR {
        msg!("ERROR: Wrong account type - expected AdminConfig");
        return Err(ProgramError::Custom(ERR_WRONG_DISCRIMINATOR));
    }

    // Now safe to read as AdminConfig
    let admin = read_pubkey(&data[8..40]);

    if admin != *authority.key() {
        return Err(ProgramError::Custom(ERR_UNAUTHORIZED));
    }

    if !authority.is_signer() {
        return Err(ProgramError::Custom(ERR_UNAUTHORIZED));
    }

    drop(data);

    let mut data = config.try_borrow_mut_data()?;
    data[40..48].copy_from_slice(&new_fee.to_le_bytes());

    msg!("SECURE: Fee updated with discriminator verification");
    Ok(())
}

#[inline]
fn read_pubkey(data: &[u8]) -> Pubkey {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data[..32]);
    Pubkey::from(bytes)
}
