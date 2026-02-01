//! # Pattern 2: Missing Owner Check (Pinocchio)
//!
//! Demonstrates trusting account data without verifying account ownership.
//! This is the vulnerability that led to the $326M Wormhole hack.

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

const IX_PROCESS_VULNERABLE: u8 = 0;
const IX_PROCESS_SECURE: u8 = 1;

const ERR_INVALID_OWNER: u32 = 2001;
const ERR_TREASURY_INACTIVE: u32 = 2002;

/// Our program ID - accounts we trust must be owned by this
const PROGRAM_ID: [u8; 32] = [
    0x6d, 0x8d, 0xa3, 0x9c, 0x42, 0x7f, 0x1b, 0x2a,
    0x5e, 0x9f, 0x3c, 0x8b, 0x7d, 0x4e, 0x6a, 0x1f,
    0x2b, 0x9c, 0x8d, 0x5e, 0x3f, 0x7a, 0x4c, 0x6b,
    0x1d, 0x8e, 0x9f, 0x2a, 0x5b, 0x3c, 0x7d, 0x4e,
];

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = instruction_data
        .first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *instruction {
        IX_PROCESS_VULNERABLE => process_vulnerable(accounts),
        IX_PROCESS_SECURE => process_secure(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ============================================================================
// VULNERABLE: Does NOT check account owner
// ============================================================================
// ISSUE: We read data from the treasury account without verifying that it
//        is owned by our program. An attacker can create a fake account
//        with arbitrary data and pass it in.
//
// WORMHOLE ATTACK (Feb 2022, $326M):
//   1. Attacker created a fake SignatureSet account (not owned by Wormhole)
//   2. Filled it with data that looked like valid guardian signatures
//   3. Passed it to Wormhole's verify function
//   4. Wormhole trusted the data and approved a 120,000 ETH transfer
// ============================================================================
fn process_vulnerable(accounts: &[AccountInfo]) -> ProgramResult {
    let treasury = &accounts[0];
    let authority = &accounts[1];

    // VULNERABLE: Directly reading account data without checking owner!
    // This data could come from ANY program - completely fabricated.
    let data = treasury.try_borrow_data()?;

    // Skip 8-byte discriminator, read authority at offset 8
    let stored_authority = read_pubkey(&data[8..40]);

    // Read balance at offset 40
    let balance = u64::from_le_bytes(
        data[40..48].try_into().map_err(|_| ProgramError::InvalidInstructionData)?
    );

    // Read is_active flag at offset 48
    let is_active = data[48] != 0;

    if !is_active {
        return Err(ProgramError::Custom(ERR_TREASURY_INACTIVE));
    }

    // NOTE: We never checked treasury.owner() == our program_id!
    // An attacker's fake account passes all these checks.

    msg!("VULNERABLE: Processed treasury without owner check");
    msg!("Authority and balance could be completely fake!");

    Ok(())
}

// ============================================================================
// SECURE: Verifies account owner before trusting data
// ============================================================================
// FIX: Check that the account is owned by our program before reading data.
// If the owner doesn't match, reject the account immediately.
//
// This is what Anchor's Account<T> type does automatically.
// ============================================================================
fn process_secure(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let treasury = &accounts[0];
    let authority = &accounts[1];

    // SECURE: Verify the treasury account is owned by our program
    // Note: owner() is unsafe in Pinocchio as it's a raw pointer dereference
    let treasury_owner = unsafe { treasury.owner() };
    if treasury_owner != program_id {
        msg!("ERROR: Treasury not owned by this program");
        return Err(ProgramError::Custom(ERR_INVALID_OWNER));
    }

    // Now we can trust the data
    let data = treasury.try_borrow_data()?;

    let stored_authority = read_pubkey(&data[8..40]);
    let balance = u64::from_le_bytes(
        data[40..48].try_into().map_err(|_| ProgramError::InvalidInstructionData)?
    );
    let is_active = data[48] != 0;

    if !is_active {
        return Err(ProgramError::Custom(ERR_TREASURY_INACTIVE));
    }

    // Verify signer matches stored authority
    if !authority.is_signer() || stored_authority != *authority.key() {
        return Err(ProgramError::IllegalOwner);
    }

    msg!("SECURE: Processed treasury with owner verification");

    Ok(())
}

#[inline]
fn read_pubkey(data: &[u8]) -> Pubkey {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data[..32]);
    Pubkey::from(bytes)
}
