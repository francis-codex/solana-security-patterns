# Deep Dive: Anatomy of Solana's Costliest Vulnerabilities

This document explores the security patterns in this repository through the lens of real-world exploits, showing how simple oversights lead to catastrophic losses.

## The $326 Million Lesson: Wormhole and Account Ownership

On February 2, 2022, an attacker exploited the Wormhole bridge for $326 million—one of the largest DeFi hacks in history. The root cause? **A missing owner check.**

### What Happened

Wormhole's Solana program verified guardian signatures before processing bridge transfers. The verification logic checked that a `SignatureSet` account contained valid signatures from trusted guardians.

The flaw: the program used raw `AccountInfo` for the signature account and manually deserialized it **without verifying the account's owner**.

```rust
// Simplified vulnerable pattern
pub fn verify_signatures(ctx: Context<VerifySignatures>) -> Result<()> {
    // VULNERABLE: signature_set is AccountInfo, not Account<SignatureSet>
    let data = ctx.accounts.signature_set.try_borrow_data()?;

    // Deserialize and trust the data...
    let signatures = deserialize_signatures(&data)?;

    // If signatures look valid, approve the transfer
    if signatures.guardian_count >= QUORUM {
        approve_transfer(...);
    }
}
```

### The Attack

1. Attacker deployed their own program
2. Created an account owned by their program with data matching `SignatureSet` layout
3. Filled in fake "guardian signatures" that passed format validation
4. Passed this spoofed account to Wormhole's verification function
5. Wormhole deserialized it, saw "valid" signatures, approved a 120,000 ETH transfer

The fix was trivial:

```rust
// SECURE: Use Account<T> which verifies owner == program_id
pub struct VerifySignatures<'info> {
    pub signature_set: Account<'info, SignatureSet>,  // Owner auto-checked
}
```

### The Pattern

This is **Pattern 2** in our repository. The vulnerable instruction uses `AccountInfo`:

```rust
#[derive(Accounts)]
pub struct ProcessVulnerable<'info> {
    /// CHECK: VULNERABLE
    pub treasury: AccountInfo<'info>,
}
```

The secure version uses `Account<T>`:

```rust
#[derive(Accounts)]
pub struct ProcessSecure<'info> {
    pub treasury: Account<'info, Treasury>,
}
```

**Cost of the bug:** $326,000,000

**Cost of the fix:** Changing one type annotation

---

## The Signature That Wasn't: Understanding Signer Checks

Missing signer checks are the most common vulnerability in Solana programs. Unlike Ethereum where `msg.sender` is implicitly the signer, Solana explicitly passes accounts and developers must verify signatures.

### The Trap

Consider this innocent-looking code:

```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: AccountInfo<'info>,  // Looks like it checks authority...
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}
```

The `has_one = authority` constraint verifies that `vault.authority == authority.key()`. This feels secure—we're checking that the right authority is passed.

**But it doesn't check that the authority signed the transaction.**

An attacker can:
1. Look up any vault's authority pubkey (it's on-chain, public data)
2. Pass that pubkey as the `authority` account without signing
3. The `has_one` check passes because the pubkeys match
4. Drain the vault

### The Fix

```rust
pub authority: Signer<'info>,  // Now MUST sign the transaction
```

This is **Pattern 1** in our repository. The distinction between `AccountInfo` and `Signer` is the difference between a secure protocol and a drained treasury.

---

## Silent Overflow: When Math Lies

Rust is famous for memory safety, but it has a footgun: **release builds wrap on overflow**.

```rust
let a: u64 = u64::MAX;
let b = a + 1;  // In debug: panic! In release: b = 0
```

Solana BPF programs compile in release mode. Every arithmetic operation is a potential vulnerability.

### The Exploit

```rust
pub fn burn(ctx: Context<Burn>, amount: u64) -> Result<()> {
    let user = &mut ctx.accounts.user;

    // User has 10 tokens, tries to burn 11
    user.balance = user.balance - amount;  // 10 - 11 = 18446744073709551615

    // User now has u64::MAX tokens
}
```

The attacker starts with 10 tokens and ends with 18 quintillion.

### The Fix

```rust
user.balance = user.balance
    .checked_sub(amount)
    .ok_or(ErrorCode::InsufficientFunds)?;
```

This is **Pattern 3**. Modern Anchor enables overflow checks by default, but the vulnerability still appears in:
- Programs using raw arithmetic operators
- Legacy code
- Programs that explicitly disable checks for "gas optimization"

---

## The Discriminator: Solana's Type System

Anchor programs prefix every account with an 8-byte discriminator: `sha256("account:{TypeName}")[..8]`. This discriminator is the **only thing** distinguishing account types at the binary level.

Consider two types with identical layouts:

```rust
#[account]
pub struct AdminConfig {
    pub admin: Pubkey,      // offset 8-40
    pub fee: u64,           // offset 40-48
}

#[account]
pub struct UserData {
    pub authority: Pubkey,  // offset 8-40  (same!)
    pub balance: u64,       // offset 40-48 (same!)
}
```

If a program uses `UncheckedAccount` and reads bytes at offset 8, it cannot tell these types apart. An attacker creates a `UserData` with their key and passes it as an `AdminConfig`.

This is **Pattern 6: Type Cosplay**. The fix is always the same: use `Account<T>` to enforce discriminator checks.

---

## Testing Strategy: Prove the Exploit, Prove the Fix

Each pattern in this repository includes three types of tests:

### 1. Exploit Test (proves vulnerability exists)

```rust
#[test]
fn exploit_works() {
    // Set up attack scenario
    // Execute vulnerable instruction
    // Assert: attack succeeded
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);
}
```

### 2. Secure Rejection Test (proves fix works)

```rust
#[test]
fn secure_rejects_attack() {
    // Same attack scenario
    // Execute secure instruction
    // Assert: attack rejected with specific error
    mollusk.process_and_validate_instruction(
        &ix,
        &accounts,
        &[Check::err(ProgramError::Custom(ERROR_CODE))]
    );
}
```

### 3. Sanity Test (proves fix doesn't break legitimate use)

```rust
#[test]
fn secure_allows_legitimate_use() {
    // Legitimate scenario
    // Execute secure instruction
    // Assert: succeeded
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);
}
```

This three-part structure ensures:
- The vulnerability is real (not theoretical)
- The fix actually prevents the attack
- The fix doesn't over-restrict legitimate operations

---

## Defense in Depth: Anchor's Safety Net

Anchor provides automatic protection against most patterns in this repository:

| Pattern | Anchor Protection | How to Bypass (and lose money) |
|---------|------------------|-------------------------------|
| Missing Signer | `Signer<'info>` type | Use `AccountInfo` |
| Missing Owner | `Account<T>` type | Use `AccountInfo`/`UncheckedAccount` |
| Integer Overflow | `overflow-checks = true` | Disable in Cargo.toml |
| Re-initialization | `init` constraint | Use `init_if_needed` carelessly |
| PDA Bump | `seeds` + `bump` constraints | Accept bump as instruction arg |
| Type Cosplay | `Account<T>` discriminator check | Use `UncheckedAccount` |

The common thread: **vulnerabilities emerge when developers bypass Anchor's typed account system**.

Every time you write `AccountInfo` or `UncheckedAccount`, you're opting out of Anchor's safety guarantees. Sometimes this is necessary (CPI, native programs), but it should always trigger extra scrutiny.

---

## Checklist for Auditors

When reviewing Solana programs, check for:

- [ ] **Signer checks**: Is every authority account a `Signer<'info>`?
- [ ] **Owner checks**: Are accounts using `Account<T>` or manually verifying `owner`?
- [ ] **Arithmetic**: Is all math using `checked_*` methods?
- [ ] **Initialization guards**: Can `init` instructions be called twice?
- [ ] **PDA derivation**: Are bumps derived on-chain or accepted as arguments?
- [ ] **Type safety**: Are there any `UncheckedAccount` or `AccountInfo` deserializations?
- [ ] **Cross-program invocations**: Are CPI target programs verified?
- [ ] **Privilege escalation**: Can a user account impersonate an admin account?

---

## Conclusion

The vulnerabilities in this repository share a common theme: **trusting unverified data**. Whether it's trusting a signature that wasn't checked, an owner that wasn't verified, or arithmetic that wasn't bounded—the pattern is always the same.

Solana's account model is explicit. Unlike EVM where the runtime enforces certain invariants, Solana programs must verify everything themselves. Anchor automates most of these checks, but only when you use its type system correctly.

The $326 million Wormhole hack was caused by a single line using `AccountInfo` instead of `Account<T>`. Learn from these patterns. Write secure code. Use the type system.

---

*This deep dive accompanies the [Solana Security Patterns](README.md) repository. Each vulnerability discussed here has working exploit code and tests you can run yourself.*
