# Pattern 4: Re-initialization Attack

**Allowing an account to be initialized more than once, enabling hostile takeover.**

## The Vulnerability

If an account can be initialized multiple times, an attacker can overwrite its state after the legitimate owner sets it up. This lets them:

- **Replace the authority** with their own key (seize control)
- **Reset balances** to zero (steal deposited funds)
- **Clear security flags** (bypass checks that were enabled)

## Real-World Impact

Multiple DeFi protocols have been exploited when config or vault accounts could be re-initialized. The attacker waits for the legitimate owner to set up the account (often depositing funds), then calls the init function again to become the new authority.

## Vulnerable Code

```rust
#[derive(Accounts)]
pub struct InitVulnerable<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    pub authority: Signer<'info>,
}

pub fn init_vulnerable(ctx: Context<InitVulnerable>) -> Result<()> {
    let config = &mut ctx.accounts.config;

    // VULNERABLE: No check for existing initialization
    // Attacker can overwrite the authority at any time
    config.authority = ctx.accounts.authority.key();
    config.is_initialized = true;
    config.vault_balance = 0;

    Ok(())
}
```

## Secure Code

```rust
pub fn init_secure(ctx: Context<InitSecure>) -> Result<()> {
    let config = &mut ctx.accounts.config;

    // SECURE: Reject if already initialized
    require!(!config.is_initialized, ErrorCode::AlreadyInitialized);

    config.authority = ctx.accounts.authority.key();
    config.is_initialized = true;
    config.vault_balance = 0;

    Ok(())
}

// OR use Anchor's init constraint (framework-idiomatic):
#[derive(Accounts)]
pub struct InitAnchorNative<'info> {
    #[account(init, payer = authority, space = 8 + Config::INIT_SPACE)]
    pub config: Account<'info, Config>,  // <-- Can only be called on new accounts
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

## The Fix

Three approaches, in order of preference:

1. **Use Anchor's `init` constraint** — Only works on accounts with zero lamports and no data. Cannot be re-invoked.
2. **Check `is_initialized` flag** — Reject if the account was already set up.
3. **Use PDAs with unique seeds** — Each combination of seeds creates a unique address that can only be initialized once.

## Test It

```bash
# Build the program
cargo build-sbf --manifest-path patterns/04-reinitialization-attack/anchor/Cargo.toml

# Run exploit tests
SBF_OUT_DIR=target/deploy cargo test -p test-reinitialization -- --nocapture
```

**What the tests prove:**
- `exploit_reinit_overwrites_authority` — Attacker overwrites Alice's authority with their own key
- `secure_blocks_reinit` — Secure version rejects re-initialization (error 6000: AlreadyInitialized)
- `secure_allows_first_init` — First initialization works normally

## Key Takeaway

**Initialization should be a one-time operation. Use `init` constraints or explicit guards—never assume an instruction will only be called once.**
