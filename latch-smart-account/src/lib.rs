#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::Hash,
    panic_with_error,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, Map, String, Symbol, Val, Vec,
};
use stellar_accounts::smart_account::{
    self as smart_account, AuthPayload, ContextRule, ContextRuleType, ExecutionEntryPoint, Signer,
    SmartAccount, SmartAccountError, SMART_ACCOUNT_EXTEND_AMOUNT, SMART_ACCOUNT_TTL_THRESHOLD,
};
use stellar_contract_utils::upgradeable::{self as upgradeable, Upgradeable};

// ################## CONSTANTS ##################

/// Number of ledgers in one day on Stellar (approx. 5 seconds per ledger).
pub const DAY_IN_LEDGERS: u32 = 17280;

/// Default extended inactivity delay required before fallback recovery can be
/// executed: 14 days of inactivity (241,920 ledgers).
pub const DEFAULT_RECOVERY_INACTIVITY_DELAY_LEDGERS: u32 = 14 * DAY_IN_LEDGERS;

/// Maximum number of secondary recovery signers permitted in a recovery
/// configuration.
pub const MAX_RECOVERY_SIGNERS: u32 = 20;

/// Record of a satellite contract this account has deployed via
/// `deploy_contract`, kept for client-side discoverability without needing
/// an off-chain indexer.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct DeployedContract {
    pub address: Address,
    pub wasm_hash: BytesN<32>,
}

/// Configuration for the secondary threshold fallback recovery mechanism.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RecoveryConfig {
    /// Secondary recovery signers (e.g. social recovery guardians or backup
    /// hardware keys).
    pub recovery_signers: Vec<Signer>,
    /// Minimum number of recovery signers required to authorize recovery.
    pub threshold: u32,
    /// Extended inactivity delay (in host ledgers) required before recovery can
    /// be triggered.
    pub inactivity_delay_ledgers: u32,
}

#[contracttype]
pub enum LatchSmartAccountStorageKey {
    DeployedContractCount,
    DeployedContract(u32),
    /// Host ledger sequence number when the primary account signers were last
    /// active.
    LastActiveLedger,
    /// Configuration for secondary threshold fallback recovery.
    RecoveryConfig,
    /// Anti-replay nonce for recovery operations.
    RecoveryNonce,
}

/// Error codes for `LatchSmartAccount`'s own methods, distinct from
/// `SmartAccountError` (the upstream `stellar-accounts` crate's error type,
/// numbered 3000+). Numbered starting at 4000 so a raw error code seen on
/// this contract is unambiguous about which enum it came from.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum LatchSmartAccountError {
    /// No deployed contract is recorded at the requested index.
    DeployedContractNotFound = 4000,
    /// The deployed-contract counter or math calculation has reached `u32::MAX`
    /// / `u64::MAX`.
    MathOverflow = 4001,
    /// No recovery configuration is installed on this account.
    RecoveryNotConfigured = 4002,
    /// Recovery configuration parameters are invalid.
    InvalidRecoveryConfig = 4003,
    /// Required inactivity delay has not elapsed yet based on host ledger
    /// sequence numbers.
    InactivityDelayNotMet = 4004,
    /// Threshold of required recovery signers was not met.
    RecoveryThresholdNotMet = 4005,
    /// Signer provided is not in the configured secondary recovery signers set.
    UnauthorizedRecoverySigner = 4006,
    /// Duplicate recovery signer signature provided.
    DuplicateRecoverySigner = 4007,
    /// The new signers vector for account recovery cannot be empty.
    EmptyNewSigners = 4008,
}

/// Event emitted when this account deploys a satellite contract via
/// `deploy_contract`.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractDeployed {
    #[topic]
    pub address: Address,
    pub wasm_hash: BytesN<32>,
}

/// Event emitted when a fallback recovery configuration is installed or
/// updated.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryConfigured {
    #[topic]
    pub smart_account: Address,
    pub threshold: u32,
    pub inactivity_delay_ledgers: u32,
}

/// Event emitted when a fallback recovery configuration is removed.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRemoved {
    #[topic]
    pub smart_account: Address,
}

/// Event emitted when primary activity is explicitly recorded or refreshed.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityRecorded {
    #[topic]
    pub smart_account: Address,
    pub ledger_sequence: u32,
}

/// Event emitted when secondary threshold recovery replaces signers on an
/// account context rule.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountRecovered {
    #[topic]
    pub smart_account: Address,
    pub context_rule_id: u32,
    pub recovered_at_ledger: u32,
}

// ################## EVENT EMISSION HELPERS ##################

fn emit_recovery_configured(
    e: &Env,
    smart_account: &Address,
    threshold: u32,
    inactivity_delay_ledgers: u32,
) {
    RecoveryConfigured {
        smart_account: smart_account.clone(),
        threshold,
        inactivity_delay_ledgers,
    }
    .publish(e);
}

fn emit_recovery_removed(e: &Env, smart_account: &Address) {
    RecoveryRemoved { smart_account: smart_account.clone() }.publish(e);
}

fn emit_activity_recorded(e: &Env, smart_account: &Address, ledger_sequence: u32) {
    ActivityRecorded { smart_account: smart_account.clone(), ledger_sequence }.publish(e);
}

fn emit_account_recovered(
    e: &Env,
    smart_account: &Address,
    context_rule_id: u32,
    recovered_at_ledger: u32,
) {
    AccountRecovered { smart_account: smart_account.clone(), context_rule_id, recovered_at_ledger }
        .publish(e);
}

fn compute_recovery_digest(
    e: &Env,
    account: &Address,
    context_rule_id: u32,
    new_signers: &Vec<Signer>,
    nonce: u64,
) -> Hash<32> {
    let mut payload = Bytes::new(e);
    payload.append(&String::from_str(e, "recover_signers").to_bytes());
    payload.append(&account.to_xdr(e));
    payload.append(&context_rule_id.to_xdr(e));
    payload.append(&new_signers.to_xdr(e));
    payload.append(&nonce.to_xdr(e));
    e.crypto().sha256(&payload)
}

#[contract]
pub struct LatchSmartAccount;

#[contractimpl]
impl LatchSmartAccount {
    /// Contract constructor — invoked exactly once by the host as part of
    /// `create_contract_v2` (`deploy_v2`) and never callable afterward, so it
    /// needs no "already initialized" guard or `require_auth`: the deploying
    /// transaction authorizes the whole creation, and the host will not
    /// dispatch a later invocation to `__constructor`. Installs the initial
    /// `Default` context rule with the deployer-supplied signers/policies and
    /// records the initial creation ledger as `LastActiveLedger`.
    pub fn __constructor(e: &Env, signers: Vec<Signer>, policies: Map<Address, Val>) {
        smart_account::add_context_rule(
            e,
            &ContextRuleType::Default,
            &String::from_str(e, "default"),
            None,
            &signers,
            &policies,
        );
        let current_ledger = e.ledger().sequence();
        e.storage().instance().set(&LatchSmartAccountStorageKey::LastActiveLedger, &current_ledger);
    }

    pub fn batch_add_signer(e: &Env, context_rule_id: u32, signers: Vec<Signer>) {
        e.current_contract_address().require_auth();
        smart_account::batch_add_signer(e, context_rule_id, &signers);
    }

    /// Deploys a new contract owned by this account, deriving its address
    /// from this account (the deployer) and `salt` — the same primitive
    /// `factory-contract` uses to deploy accounts, just invoked from within
    /// an account instead of the factory.
    ///
    /// # Errors
    ///
    /// * [`LatchSmartAccountError::MathOverflow`] - If the deployed-contract
    ///   counter has reached `u32::MAX`.
    ///
    /// # Events
    ///
    /// * topics - `["contract_deployed", address: Address]`
    /// * data - `[wasm_hash: BytesN<32>]`
    pub fn deploy_contract(
        e: &Env,
        wasm_hash: BytesN<32>,
        salt: BytesN<32>,
        constructor_args: Vec<Val>,
    ) -> Address {
        let address =
            e.deployer().with_current_contract(salt).deploy_v2(wasm_hash.clone(), constructor_args);

        let index = Self::get_deployed_contract_count(e);
        let next_count = index
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::MathOverflow));
        e.storage()
            .instance()
            .set(&LatchSmartAccountStorageKey::DeployedContractCount, &next_count);

        let key = LatchSmartAccountStorageKey::DeployedContract(index);
        let record = DeployedContract { address: address.clone(), wasm_hash: wasm_hash.clone() };
        e.storage().persistent().set(&key, &record);
        e.storage().persistent().extend_ttl(
            &key,
            SMART_ACCOUNT_TTL_THRESHOLD,
            SMART_ACCOUNT_EXTEND_AMOUNT,
        );

        ContractDeployed { address: address.clone(), wasm_hash }.publish(e);

        address
    }

    /// Returns the number of contracts this account has deployed via
    /// `deploy_contract`. Defaults to `0`.
    pub fn get_deployed_contract_count(e: &Env) -> u32 {
        e.storage().instance().get(&LatchSmartAccountStorageKey::DeployedContractCount).unwrap_or(0)
    }

    /// Returns the `index`-th contract this account has deployed via
    /// `deploy_contract`, in deployment order.
    ///
    /// # Errors
    ///
    /// * [`LatchSmartAccountError::DeployedContractNotFound`] - If no deployed
    ///   contract is recorded at `index`.
    pub fn get_deployed_contract(e: &Env, index: u32) -> DeployedContract {
        let key = LatchSmartAccountStorageKey::DeployedContract(index);
        e.storage()
            .persistent()
            .get::<_, DeployedContract>(&key)
            .inspect(|_| {
                e.storage().persistent().extend_ttl(
                    &key,
                    SMART_ACCOUNT_TTL_THRESHOLD,
                    SMART_ACCOUNT_EXTEND_AMOUNT,
                );
            })
            .unwrap_or_else(|| {
                panic_with_error!(e, LatchSmartAccountError::DeployedContractNotFound)
            })
    }

    // ################## FALLBACK RECOVERY MECHANISM ##################

    /// Configures the secondary threshold fallback recovery mechanism for this
    /// smart account. Requires self-authorization from the account.
    ///
    /// Allows secondary signers (social recovery guardians or backup hardware
    /// keys) to recover account signers after an extended period of inactivity.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `recovery_signers` - The secondary signers.
    /// * `threshold` - The minimum number of recovery signers required to
    ///   execute recovery.
    /// * `inactivity_delay_ledgers` - The required delay in host ledgers of
    ///   inactivity before recovery is permitted (e.g. 14 days = 241,920
    ///   ledgers). If 0 is passed, defaults to
    ///   [`DEFAULT_RECOVERY_INACTIVITY_DELAY_LEDGERS`].
    ///
    /// # Errors
    ///
    /// * [`LatchSmartAccountError::InvalidRecoveryConfig`] - If threshold is 0,
    ///   threshold exceeds recovery signers count, recovery signers is empty or
    ///   exceeds [`MAX_RECOVERY_SIGNERS`], or contains duplicate signers.
    pub fn set_recovery_config(
        e: &Env,
        recovery_signers: Vec<Signer>,
        threshold: u32,
        inactivity_delay_ledgers: u32,
    ) {
        e.current_contract_address().require_auth();

        if recovery_signers.is_empty()
            || recovery_signers.len() > MAX_RECOVERY_SIGNERS
            || threshold == 0
            || threshold > recovery_signers.len()
        {
            panic_with_error!(e, LatchSmartAccountError::InvalidRecoveryConfig);
        }

        // Validate no duplicates in recovery_signers
        for i in 0..recovery_signers.len() {
            let s_i = recovery_signers.get(i).unwrap();
            for j in (i + 1)..recovery_signers.len() {
                let s_j = recovery_signers.get(j).unwrap();
                if s_i == s_j {
                    panic_with_error!(e, LatchSmartAccountError::InvalidRecoveryConfig);
                }
            }
        }

        let delay = if inactivity_delay_ledgers == 0 {
            DEFAULT_RECOVERY_INACTIVITY_DELAY_LEDGERS
        } else {
            inactivity_delay_ledgers
        };

        let config = RecoveryConfig {
            recovery_signers: recovery_signers.clone(),
            threshold,
            inactivity_delay_ledgers: delay,
        };

        e.storage().instance().set(&LatchSmartAccountStorageKey::RecoveryConfig, &config);

        emit_recovery_configured(e, &e.current_contract_address(), threshold, delay);
    }

    /// Returns the active recovery configuration.
    ///
    /// # Errors
    ///
    /// * [`LatchSmartAccountError::RecoveryNotConfigured`] - If no recovery
    ///   configuration is set on this account.
    pub fn get_recovery_config(e: &Env) -> RecoveryConfig {
        e.storage()
            .instance()
            .get(&LatchSmartAccountStorageKey::RecoveryConfig)
            .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::RecoveryNotConfigured))
    }

    /// Removes the recovery configuration from the account. Requires
    /// self-authorization.
    ///
    /// # Errors
    ///
    /// * [`LatchSmartAccountError::RecoveryNotConfigured`] - If no recovery
    ///   configuration is installed.
    pub fn remove_recovery_config(e: &Env) {
        e.current_contract_address().require_auth();
        if !e.storage().instance().has(&LatchSmartAccountStorageKey::RecoveryConfig) {
            panic_with_error!(e, LatchSmartAccountError::RecoveryNotConfigured);
        }
        e.storage().instance().remove(&LatchSmartAccountStorageKey::RecoveryConfig);
        emit_recovery_removed(e, &e.current_contract_address());
    }

    /// Returns the host ledger sequence number when the account was last
    /// active. Defaults to 0 if not yet recorded.
    pub fn get_last_active_ledger(e: &Env) -> u32 {
        e.storage().instance().get(&LatchSmartAccountStorageKey::LastActiveLedger).unwrap_or(0)
    }

    /// Explicitly refreshes the account's last active ledger sequence to the
    /// current host ledger sequence number. Requires self-authorization from
    /// the primary signers, resetting any accumulated inactivity timer.
    pub fn touch_activity(e: &Env) {
        e.current_contract_address().require_auth();
        let current_ledger = e.ledger().sequence();
        e.storage().instance().set(&LatchSmartAccountStorageKey::LastActiveLedger, &current_ledger);
        emit_activity_recorded(e, &e.current_contract_address(), current_ledger);
    }

    /// Checks whether the account has been inactive for at least the configured
    /// inactivity delay ledgers, making recovery eligible for execution.
    pub fn is_recovery_eligible(e: &Env) -> bool {
        let Some(config) = e
            .storage()
            .instance()
            .get::<_, RecoveryConfig>(&LatchSmartAccountStorageKey::RecoveryConfig)
        else {
            return false;
        };
        let current_ledger = e.ledger().sequence();
        let last_active = Self::get_last_active_ledger(e);
        let elapsed = current_ledger.saturating_sub(last_active);
        elapsed >= config.inactivity_delay_ledgers
    }

    /// Returns the current recovery nonce used for signature replay protection.
    pub fn get_recovery_nonce(e: &Env) -> u64 {
        e.storage().instance().get(&LatchSmartAccountStorageKey::RecoveryNonce).unwrap_or(0)
    }

    /// Computes the authentication digest that secondary recovery signers must
    /// sign for a recovery ceremony with the current recovery nonce.
    pub fn get_recovery_digest(
        e: &Env,
        context_rule_id: u32,
        new_signers: Vec<Signer>,
    ) -> BytesN<32> {
        let nonce = Self::get_recovery_nonce(e);
        let digest = compute_recovery_digest(
            e,
            &e.current_contract_address(),
            context_rule_id,
            &new_signers,
            nonce,
        );
        digest.to_bytes()
    }

    /// Recovers the smart account by replacing the signers of the specified
    /// context rule with `new_signers`.
    ///
    /// Enforces:
    /// 1. Inactivity check verified against host ledger sequence numbers: The
    ///    elapsed ledgers since `LastActiveLedger` must be `>=
    ///    inactivity_delay_ledgers`.
    /// 2. Recovery threshold rules: At least `threshold` unique secondary
    ///    recovery signers must authenticate the recovery payload digest.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `context_rule_id` - The ID of the context rule whose signers are being
    ///   replaced (e.g. 0 for the default rule).
    /// * `new_signers` - The replacement signers.
    /// * `signatures` - A map of `Signer` to signature data (`Bytes`) from the
    ///   secondary recovery signers.
    ///
    /// # Errors
    ///
    /// * [`LatchSmartAccountError::RecoveryNotConfigured`] - If recovery is not
    ///   configured.
    /// * [`LatchSmartAccountError::EmptyNewSigners`] - If `new_signers` is
    ///   empty.
    /// * [`LatchSmartAccountError::InvalidRecoveryConfig`] - If `new_signers`
    ///   contains duplicates.
    /// * [`LatchSmartAccountError::InactivityDelayNotMet`] - If the inactivity
    ///   delay has not elapsed.
    /// * [`LatchSmartAccountError::UnauthorizedRecoverySigner`] - If a provided
    ///   signer is not in the recovery set.
    /// * [`LatchSmartAccountError::DuplicateRecoverySigner`] - If a recovery
    ///   signer provided duplicate signatures.
    /// * [`LatchSmartAccountError::RecoveryThresholdNotMet`] - If fewer than
    ///   `threshold` signatures are authenticated.
    /// * [`LatchSmartAccountError::MathOverflow`] - If internal counters
    ///   overflow.
    pub fn recover_signers(
        e: &Env,
        context_rule_id: u32,
        new_signers: Vec<Signer>,
        signatures: Map<Signer, Bytes>,
    ) {
        let config = Self::get_recovery_config(e);

        if new_signers.is_empty() {
            panic_with_error!(e, LatchSmartAccountError::EmptyNewSigners);
        }

        // Validate no duplicates in new_signers
        for i in 0..new_signers.len() {
            let s_i = new_signers.get(i).unwrap();
            for j in (i + 1)..new_signers.len() {
                let s_j = new_signers.get(j).unwrap();
                if s_i == s_j {
                    panic_with_error!(e, LatchSmartAccountError::InvalidRecoveryConfig);
                }
            }
        }

        // 1. Inactivity check verified against host ledger sequence numbers
        let current_ledger = e.ledger().sequence();
        let last_active = Self::get_last_active_ledger(e);
        let elapsed = current_ledger.saturating_sub(last_active);
        if elapsed < config.inactivity_delay_ledgers {
            panic_with_error!(e, LatchSmartAccountError::InactivityDelayNotMet);
        }

        // 2. Anti-replay recovery nonce
        let nonce = Self::get_recovery_nonce(e);
        let auth_digest = compute_recovery_digest(
            e,
            &e.current_contract_address(),
            context_rule_id,
            &new_signers,
            nonce,
        );

        // 3. Enforce recovery threshold rules
        let mut authenticated_count: u32 = 0;
        let mut seen_signers: Vec<Signer> = Vec::new(e);

        for (signer, sig_data) in signatures.iter() {
            if !config.recovery_signers.contains(&signer) {
                panic_with_error!(e, LatchSmartAccountError::UnauthorizedRecoverySigner);
            }
            if seen_signers.contains(&signer) {
                panic_with_error!(e, LatchSmartAccountError::DuplicateRecoverySigner);
            }
            seen_signers.push_back(signer.clone());

            // Authenticate signer (handles both Delegated and External verifiers)
            smart_account::authenticate(e, &auth_digest, &signer, &sig_data);
            authenticated_count = authenticated_count
                .checked_add(1)
                .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::MathOverflow));
        }

        if authenticated_count < config.threshold {
            panic_with_error!(e, LatchSmartAccountError::RecoveryThresholdNotMet);
        }

        // 4. Rotate signers on the specified context rule
        let old_rule = smart_account::get_context_rule(e, context_rule_id);
        let mut to_add = Vec::new(e);
        for signer in new_signers.iter() {
            if !old_rule.signers.contains(&signer) {
                to_add.push_back(signer);
            }
        }
        if !to_add.is_empty() {
            smart_account::batch_add_signer(e, context_rule_id, &to_add);
        }

        for old_signer in old_rule.signers.iter() {
            if !new_signers.contains(&old_signer) {
                let signer_id = <Self as SmartAccount>::get_signer_id(e, old_signer.clone());
                smart_account::remove_signer(e, context_rule_id, signer_id);
            }
        }

        // 5. Update state: advance nonce and record current ledger as active
        let next_nonce = nonce
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::MathOverflow));
        e.storage().instance().set(&LatchSmartAccountStorageKey::RecoveryNonce, &next_nonce);
        e.storage().instance().set(&LatchSmartAccountStorageKey::LastActiveLedger, &current_ledger);

        emit_account_recovered(e, &e.current_contract_address(), context_rule_id, current_ledger);
    }
}

#[contractimpl]
impl CustomAccountInterface for LatchSmartAccount {
    type Error = SmartAccountError;
    type Signature = AuthPayload;

    fn __check_auth(
        e: Env,
        signature_payload: Hash<32>,
        signatures: AuthPayload,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Self::Error> {
        smart_account::do_check_auth(&e, &signature_payload, &signatures, &auth_contexts)?;
        let current_ledger = e.ledger().sequence();
        e.storage().instance().set(&LatchSmartAccountStorageKey::LastActiveLedger, &current_ledger);
        Ok(())
    }
}

#[contractimpl(contracttrait)]
impl SmartAccount for LatchSmartAccount {}

#[contractimpl(contracttrait)]
impl ExecutionEntryPoint for LatchSmartAccount {}

#[contractimpl]
impl Upgradeable for LatchSmartAccount {
    fn upgrade(e: &Env, new_wasm_hash: BytesN<32>, _operator: Address) {
        e.current_contract_address().require_auth();
        upgradeable::upgrade(e, &new_wasm_hash);
    }
}

#[cfg(test)]
mod test;
