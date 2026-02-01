//! # Pattern 1: Missing Signer Check (Pinocchio)
//!
//! Demonstrates the vulnerability using Pinocchio's low-level approach.
//! Unlike Anchor, Pinocchio requires explicit manual checks for everything.

#![no_std]

// Required for no_std
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

/// Instruction discriminators (first byte of instruction data)
const IX_WITHDRAW_VULNERABLE: u8 = 0;
const IX_WITHDRAW_SECURE: u8 = 1;

/// Custom error codes
const ERR_MISSING_SIGNER: u32 = 1001;
const ERR_INVALID_AUTHORITY: u32 = 1002;
const ERR_INSUFFICIENT_FUNDS: u32 = 1003;

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = instruction_data
        .first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *instruction {
        IX_WITHDRAW_VULNERABLE => withdraw_vulnerable(accounts, instruction_data),
        IX_WITHDRAW_SECURE => withdraw_secure(accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ============================================================================
// VULNERABLE: Does NOT check is_signer on authority
// ============================================================================
// ISSUE: We read the authority pubkey and compare it to the vault's stored
//        authority, but we NEVER verify that the authority actually signed
//        the transaction. Anyone can pass any pubkey as the authority.
//
// ATTACK:
//   1. Attacker finds a vault with funds
//   2. Reads the vault's authority pubkey from on-chain data
//   3. Passes that pubkey as the authority account (without signing)
//   4. Drains the vault to their own account
// ============================================================================
fn withdraw_vulnerable(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    let recipient = &accounts[2];

    // Parse withdrawal amount from instruction data (bytes 1-8)
    let amount = u64::from_le_bytes(
        instruction_data[1..9]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // Read stored authority from vault data (skip 8-byte discriminator)
    let vault_data = vault.try_borrow_data()?;
    let stored_authority = read_pubkey(&vault_data[8..40]);

    // VULNERABLE: Only checks pubkey match, NOT signature!
    // This check passes even if authority didn't sign the transaction.
    if stored_authority != *authority.key() {
        return Err(ProgramError::Custom(ERR_INVALID_AUTHORITY));
    }

    // NOTE: We're NOT checking authority.is_signer() here!
    // That's the vulnerability.

    // Read balance from vault (offset 40)
    let balance = u64::from_le_bytes(
        vault_data[40..48]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );
    if balance < amount {
        return Err(ProgramError::Custom(ERR_INSUFFICIENT_FUNDS));
    }
    drop(vault_data);

    // Update vault balance
    let mut vault_data = vault.try_borrow_mut_data()?;
    let new_balance = balance - amount;
    vault_data[40..48].copy_from_slice(&new_balance.to_le_bytes());
    drop(vault_data);

    // Transfer lamports
    unsafe {
        *vault.borrow_mut_lamports_unchecked() -= amount;
        *recipient.borrow_mut_lamports_unchecked() += amount;
    }

    msg!("VULNERABLE: Withdrew without signer check");
    Ok(())
}

// ============================================================================
// SECURE: Explicitly checks is_signer on authority
// ============================================================================
// FIX: Before trusting the authority account, verify that:
//   1. The pubkey matches the stored authority (authorization)
//   2. The account actually signed the transaction (authentication)
//
// This is what Anchor's Signer<'info> type does automatically.
// In Pinocchio/native, we must do it ourselves.
// ============================================================================
fn withdraw_secure(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    let recipient = &accounts[2];

    let amount = u64::from_le_bytes(
        instruction_data[1..9]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // SECURE: Check that authority signed the transaction FIRST
    if !authority.is_signer() {
        msg!("ERROR: Authority must sign the transaction");
        return Err(ProgramError::Custom(ERR_MISSING_SIGNER));
    }

    // Now verify the authority matches the vault's stored authority
    let vault_data = vault.try_borrow_data()?;
    let stored_authority = read_pubkey(&vault_data[8..40]);

    if stored_authority != *authority.key() {
        return Err(ProgramError::Custom(ERR_INVALID_AUTHORITY));
    }

    let balance = u64::from_le_bytes(
        vault_data[40..48]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );
    if balance < amount {
        return Err(ProgramError::Custom(ERR_INSUFFICIENT_FUNDS));
    }
    drop(vault_data);

    // Update vault balance
    let mut vault_data = vault.try_borrow_mut_data()?;
    let new_balance = balance - amount;
    vault_data[40..48].copy_from_slice(&new_balance.to_le_bytes());
    drop(vault_data);

    // Transfer lamports
    unsafe {
        *vault.borrow_mut_lamports_unchecked() -= amount;
        *recipient.borrow_mut_lamports_unchecked() += amount;
    }

    msg!("SECURE: Withdrew with signer verification");
    Ok(())
}

/// Helper to read a Pubkey from a byte slice
#[inline]
fn read_pubkey(data: &[u8]) -> Pubkey {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data[..32]);
    Pubkey::from(bytes)
}
