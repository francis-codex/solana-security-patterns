//! # Pattern 3: Integer Overflow/Underflow (Pinocchio)
//!
//! Demonstrates arithmetic that wraps instead of failing.
//! Solana BPF programs run in release mode where overflow wraps silently.

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

const IX_MINT_VULNERABLE: u8 = 0;
const IX_BURN_VULNERABLE: u8 = 1;
const IX_MINT_SECURE: u8 = 2;
const IX_BURN_SECURE: u8 = 3;

const ERR_OVERFLOW: u32 = 3001;
const ERR_UNDERFLOW: u32 = 3002;

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = instruction_data
        .first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    let amount = u64::from_le_bytes(
        instruction_data[1..9]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    match *instruction {
        IX_MINT_VULNERABLE => mint_vulnerable(accounts, amount),
        IX_BURN_VULNERABLE => burn_vulnerable(accounts, amount),
        IX_MINT_SECURE => mint_secure(accounts, amount),
        IX_BURN_SECURE => burn_secure(accounts, amount),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ============================================================================
// VULNERABLE: Uses wrapping arithmetic
// ============================================================================
// ISSUE: In release mode (how Solana BPF compiles), overflow wraps silently.
//   - u64::MAX + 1 = 0
//   - 0 - 1 = u64::MAX
//
// ATTACK:
//   1. Attacker has balance = 10 tokens
//   2. Calls burn(11) on vulnerable instruction
//   3. balance = 10 - 11 = 18446744073709551615 (u64::MAX)
//   4. Attacker now has quintillions of tokens
// ============================================================================
fn mint_vulnerable(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let ledger = &accounts[0];

    let mut data = ledger.try_borrow_mut_data()?;

    // Read current supply (offset 40 after discriminator + authority)
    let supply = u64::from_le_bytes(data[40..48].try_into().unwrap());
    let balance = u64::from_le_bytes(data[48..56].try_into().unwrap());

    // VULNERABLE: wrapping_add - if supply is near max, wraps to 0
    let new_supply = supply.wrapping_add(amount);
    let new_balance = balance.wrapping_add(amount);

    data[40..48].copy_from_slice(&new_supply.to_le_bytes());
    data[48..56].copy_from_slice(&new_balance.to_le_bytes());

    msg!("VULNERABLE MINT: supply wrapped without error");
    Ok(())
}

fn burn_vulnerable(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let ledger = &accounts[0];

    let mut data = ledger.try_borrow_mut_data()?;

    let supply = u64::from_le_bytes(data[40..48].try_into().unwrap());
    let balance = u64::from_le_bytes(data[48..56].try_into().unwrap());

    // VULNERABLE: wrapping_sub - if balance < amount, wraps to huge number
    let new_supply = supply.wrapping_sub(amount);
    let new_balance = balance.wrapping_sub(amount);

    data[40..48].copy_from_slice(&new_supply.to_le_bytes());
    data[48..56].copy_from_slice(&new_balance.to_le_bytes());

    msg!("VULNERABLE BURN: balance wrapped without error");
    Ok(())
}

// ============================================================================
// SECURE: Uses checked arithmetic
// ============================================================================
// FIX: Use checked_add/checked_sub which return None on overflow/underflow.
// Convert None to a program error.
// ============================================================================
fn mint_secure(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let ledger = &accounts[0];

    let mut data = ledger.try_borrow_mut_data()?;

    let supply = u64::from_le_bytes(data[40..48].try_into().unwrap());
    let balance = u64::from_le_bytes(data[48..56].try_into().unwrap());

    // SECURE: checked_add returns None on overflow
    let new_supply = supply
        .checked_add(amount)
        .ok_or(ProgramError::Custom(ERR_OVERFLOW))?;
    let new_balance = balance
        .checked_add(amount)
        .ok_or(ProgramError::Custom(ERR_OVERFLOW))?;

    data[40..48].copy_from_slice(&new_supply.to_le_bytes());
    data[48..56].copy_from_slice(&new_balance.to_le_bytes());

    msg!("SECURE MINT: overflow would be rejected");
    Ok(())
}

fn burn_secure(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let ledger = &accounts[0];

    let mut data = ledger.try_borrow_mut_data()?;

    let supply = u64::from_le_bytes(data[40..48].try_into().unwrap());
    let balance = u64::from_le_bytes(data[48..56].try_into().unwrap());

    // SECURE: checked_sub returns None on underflow
    let new_balance = balance
        .checked_sub(amount)
        .ok_or(ProgramError::Custom(ERR_UNDERFLOW))?;
    let new_supply = supply
        .checked_sub(amount)
        .ok_or(ProgramError::Custom(ERR_UNDERFLOW))?;

    data[40..48].copy_from_slice(&new_supply.to_le_bytes());
    data[48..56].copy_from_slice(&new_balance.to_le_bytes());

    msg!("SECURE BURN: underflow would be rejected");
    Ok(())
}
