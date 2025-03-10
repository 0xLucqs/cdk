//! Types

use std::any::Any;
use std::sync::Arc;

use mssmt::{Branch, CompactLeaf, Db, Leaf, Node, TreeError};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::Mutex;

use crate::error::Error;
use crate::mint_url::MintUrl;
use crate::nuts::nut00::ProofsMethods;
use crate::nuts::{
    CurrencyUnit, MeltQuoteState, PaymentMethod, Proof, Proofs, PublicKey, SpendingConditions,
    State,
};
use crate::{database, Amount};

/// Melt response with proofs
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Melted {
    /// State of quote
    pub state: MeltQuoteState,
    /// Preimage of melt payment
    pub preimage: Option<String>,
    /// Melt change
    pub change: Option<Proofs>,
    /// Melt amount
    pub amount: Amount,
    /// Fee paid
    pub fee_paid: Amount,
}

impl Melted {
    /// Create new [`Melted`]
    pub fn from_proofs(
        state: MeltQuoteState,
        preimage: Option<String>,
        amount: Amount,
        proofs: Proofs,
        change_proofs: Option<Proofs>,
    ) -> Result<Self, Error> {
        let proofs_amount = proofs.total_amount()?;
        let change_amount = match &change_proofs {
            Some(change_proofs) => change_proofs.total_amount()?,
            None => Amount::ZERO,
        };

        let fee_paid = proofs_amount
            .checked_sub(amount + change_amount)
            .ok_or(Error::AmountOverflow)?;

        Ok(Self {
            state,
            preimage,
            change: change_proofs,
            amount,
            fee_paid,
        })
    }

    /// Total amount melted
    pub fn total_amount(&self) -> Amount {
        self.amount + self.fee_paid
    }
}

/// Prooinfo
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofInfo {
    /// Proof
    pub proof: Proof,
    /// y
    pub y: PublicKey,
    /// Mint Url
    pub mint_url: MintUrl,
    /// Proof State
    pub state: State,
    /// Proof Spending Conditions
    pub spending_condition: Option<SpendingConditions>,
    /// Unit
    pub unit: CurrencyUnit,
}

impl ProofInfo {
    /// Create new [`ProofInfo`]
    pub fn new(
        proof: Proof,
        mint_url: MintUrl,
        state: State,
        unit: CurrencyUnit,
    ) -> Result<Self, Error> {
        let y = proof.y()?;

        let spending_condition: Option<SpendingConditions> = (&proof.secret).try_into().ok();

        Ok(Self {
            proof,
            y,
            mint_url,
            state,
            spending_condition,
            unit,
        })
    }

    /// Check if [`Proof`] matches conditions
    pub fn matches_conditions(
        &self,
        mint_url: &Option<MintUrl>,
        unit: &Option<CurrencyUnit>,
        state: &Option<Vec<State>>,
        spending_conditions: &Option<Vec<SpendingConditions>>,
    ) -> bool {
        if let Some(mint_url) = mint_url {
            if mint_url.ne(&self.mint_url) {
                return false;
            }
        }

        if let Some(unit) = unit {
            if unit.ne(&self.unit) {
                return false;
            }
        }

        if let Some(state) = state {
            if !state.contains(&self.state) {
                return false;
            }
        }

        if let Some(spending_conditions) = spending_conditions {
            match &self.spending_condition {
                None => return false,
                Some(s) => {
                    if !spending_conditions.contains(s) {
                        return false;
                    }
                }
            }
        }

        true
    }
}

/// Key used in hashmap of ln backends to identify what unit and payment method
/// it is for
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct LnKey {
    /// Unit of Payment backend
    pub unit: CurrencyUnit,
    /// Method of payment backend
    pub method: PaymentMethod,
}

impl LnKey {
    /// Create new [`LnKey`]
    pub fn new(unit: CurrencyUnit, method: PaymentMethod) -> Self {
        Self { unit, method }
    }
}

/// Secs wuotes are valid
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct QuoteTTL {
    /// Seconds mint quote is valid
    pub mint_ttl: u64,
    /// Seconds melt quote is valid
    pub melt_ttl: u64,
}

impl QuoteTTL {
    /// Create new [`QuoteTTL`]
    pub fn new(mint_ttl: u64, melt_ttl: u64) -> QuoteTTL {
        Self { mint_ttl, melt_ttl }
    }
}

#[derive(Clone)]
pub struct ArcTreeStore(Arc<Mutex<dyn NamespaceableTreeStore<DbError = database::Error>>>);

impl ArcTreeStore {
    pub fn new(db: impl NamespaceableTreeStore<DbError = database::Error>) -> Self {
        Self(Arc::new(Mutex::new(db)))
    }
}
pub trait NamespaceableTreeStore: Db<32, Sha256> + Send + Sync + 'static {
    fn set_namespace(&mut self, namespace: &str);
    fn get_leaf(&self, key: &[u8; 32]) -> Option<Leaf<32, Sha256>>;
}
impl NamespaceableTreeStore for ArcTreeStore {
    fn set_namespace(&mut self, namespace: &str) {
        tokio::task::block_in_place(|| {
            self.0.blocking_lock().set_namespace(namespace);
        })
    }

    fn get_leaf(&self, key: &[u8; 32]) -> Option<Leaf<32, Sha256>> {
        tokio::task::block_in_place(|| self.0.blocking_lock().get_leaf(key))
    }
}

impl Db<32, Sha256> for ArcTreeStore {
    type DbError = database::Error;
    fn get_root_node(&self) -> Option<Branch<32, Sha256>> {
        tokio::task::block_in_place(|| self.0.blocking_lock().get_root_node())
    }

    fn get_children(
        &self,
        height: usize,
        key: [u8; 32],
    ) -> Result<(Node<32, Sha256>, Node<32, Sha256>), TreeError<Self::DbError>> {
        tokio::task::block_in_place(|| self.0.blocking_lock().get_children(height, key))
    }

    fn insert_leaf(&mut self, leaf: Leaf<32, Sha256>) -> Result<(), TreeError<Self::DbError>> {
        tokio::task::block_in_place(|| self.0.blocking_lock().insert_leaf(leaf))
    }

    fn insert_branch(
        &mut self,
        branch: Branch<32, Sha256>,
    ) -> Result<(), TreeError<Self::DbError>> {
        tokio::task::block_in_place(|| self.0.blocking_lock().insert_branch(branch))
    }

    fn insert_compact_leaf(
        &mut self,
        compact_leaf: CompactLeaf<32, Sha256>,
    ) -> Result<(), TreeError<Self::DbError>> {
        tokio::task::block_in_place(|| self.0.blocking_lock().insert_compact_leaf(compact_leaf))
    }

    fn empty_tree(&self) -> Arc<[Node<32, Sha256>; 257]> {
        tokio::task::block_in_place(|| self.0.blocking_lock().empty_tree())
    }

    fn update_root(&mut self, root: Branch<32, Sha256>) -> Result<(), TreeError<Self::DbError>> {
        tokio::task::block_in_place(|| self.0.blocking_lock().update_root(root))
    }

    fn delete_branch(&mut self, key: &[u8; 32]) -> Result<(), TreeError<Self::DbError>> {
        tokio::task::block_in_place(|| self.0.blocking_lock().delete_branch(key))
    }

    fn delete_leaf(&mut self, key: &[u8; 32]) -> Result<(), TreeError<Self::DbError>> {
        tokio::task::block_in_place(|| self.0.blocking_lock().delete_leaf(key))
    }

    fn delete_compact_leaf(&mut self, key: &[u8; 32]) -> Result<(), TreeError<Self::DbError>> {
        tokio::task::block_in_place(|| self.0.blocking_lock().delete_compact_leaf(key))
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::Melted;
    use crate::nuts::{Id, Proof, PublicKey};
    use crate::secret::Secret;
    use crate::Amount;

    #[test]
    fn test_melted() {
        let keyset_id = Id::from_str("00deadbeef123456").unwrap();
        let proof = Proof::new(
            Amount::from(64),
            keyset_id,
            Secret::generate(),
            PublicKey::from_hex(
                "02deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
            .unwrap(),
        );
        let melted = Melted::from_proofs(
            super::MeltQuoteState::Paid,
            Some("preimage".to_string()),
            Amount::from(64),
            vec![proof.clone()],
            None,
        )
        .unwrap();
        assert_eq!(melted.amount, Amount::from(64));
        assert_eq!(melted.fee_paid, Amount::ZERO);
        assert_eq!(melted.total_amount(), Amount::from(64));
    }

    #[test]
    fn test_melted_with_change() {
        let keyset_id = Id::from_str("00deadbeef123456").unwrap();
        let proof = Proof::new(
            Amount::from(64),
            keyset_id,
            Secret::generate(),
            PublicKey::from_hex(
                "02deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
            .unwrap(),
        );
        let change_proof = Proof::new(
            Amount::from(32),
            keyset_id,
            Secret::generate(),
            PublicKey::from_hex(
                "03deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
            .unwrap(),
        );
        let melted = Melted::from_proofs(
            super::MeltQuoteState::Paid,
            Some("preimage".to_string()),
            Amount::from(31),
            vec![proof.clone()],
            Some(vec![change_proof.clone()]),
        )
        .unwrap();
        assert_eq!(melted.amount, Amount::from(31));
        assert_eq!(melted.fee_paid, Amount::from(1));
        assert_eq!(melted.total_amount(), Amount::from(32));
    }
}
