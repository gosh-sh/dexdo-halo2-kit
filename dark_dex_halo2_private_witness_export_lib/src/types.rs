//! Minimal vendored newtypes mirroring `node-types::AccountRouting` and
//! `node-types::ThreadIdentifier`. Only the surface the exporter actually uses
//! is implemented.

use std::str::FromStr;

#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub struct AccountRouting {
    dapp_id: [u8; 32],
    account_id: [u8; 32],
}

impl AccountRouting {
    pub fn new(dapp_id: [u8; 32], account_id: [u8; 32]) -> Self {
        Self { dapp_id, account_id }
    }

    pub fn unpack_for_hash(&self) -> ([u8; 32], [u8; 32]) {
        (self.dapp_id, self.account_id)
    }
}

impl FromStr for AccountRouting {
    type Err = anyhow::Error;

    /// Accepts both encodings the node may emit:
    ///   * `"hexdapp::hexaccount"` (64 hex chars `::` 64 hex chars)
    ///   * 128 hex chars without separator (dapp || account)
    /// Also tolerates the redirect form `"::hexaccount"` (dapp = account).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((dapp, account)) = s.split_once("::") {
            let account_id = decode_32(account)?;
            let dapp_id = if dapp.is_empty() { account_id } else { decode_32(dapp)? };
            Ok(Self { dapp_id, account_id })
        } else if s.len() == 128 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            let (dapp, account) = s.split_at(64);
            Ok(Self { dapp_id: decode_32(dapp)?, account_id: decode_32(account)? })
        } else {
            Err(anyhow::anyhow!("Invalid account routing [{s}]"))
        }
    }
}

impl std::fmt::Display for AccountRouting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", hex::encode(self.dapp_id), hex::encode(self.account_id))
    }
}

fn decode_32(s: &str) -> anyhow::Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|e| anyhow::anyhow!("invalid hex: {e}"))?;
    Ok(out)
}

#[derive(Copy, Clone, Debug)]
pub struct ThreadIdentifier([u8; 34]);

impl Default for ThreadIdentifier {
    fn default() -> Self {
        Self([0; 34])
    }
}

impl std::fmt::LowerHex for ThreadIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl TryFrom<String> for ThreadIdentifier {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = hex::decode(&value).map_err(|_| anyhow::anyhow!("invalid thread_id hex"))?;
        let arr: [u8; 34] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("expected 34 bytes, got {}", v.len()))?;
        Ok(Self(arr))
    }
}
