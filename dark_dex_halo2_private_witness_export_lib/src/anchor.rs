//! Which history layer an event proof is anchored to, and the block heights
//! that decide when that anchor can be used.
//!
//! With `W` = [`HISTORY_PROOF_WINDOW_SIZE`] and the event at height `h`
//! (thread 0):
//!
//! * the node publishes the layer-`n` root covering `h` in block
//!   `T_n = ⌊h / W^n⌋·W^n + W^n`, the first multiple of `W^n` strictly above
//!   `h` (a root published exactly at `h` covers the previous window);
//! * the history cursor keeps at most `W` roots per layer and clears a full
//!   layer on its next push, so `gosh.check_layer_hash(root, n)` accepts the
//!   root while the parent block's height is in `[T_n, E_n)`, where
//!   `E_n = T_{n+1} + W^n` (acki-nacki `node/src/types/history_proof.rs`).
//!
//! An L1 root is therefore usable for `W` to `W²` blocks (~43 s to ~91 min at
//! ~3 blocks/s), an L2 root for `W²` to `W³` blocks (~91 min to ~8 days).

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use crate::poseidon::HISTORY_PROOF_WINDOW_SIZE;

/// Highest layer the circuit can anchor to: L1 plus `MAX_CHAIN_LEN` (11) links.
pub const MAX_ANCHOR_LAYER: u32 = 12;

/// Block rate assumed only for the human-readable estimates in messages.
pub const NOMINAL_BLOCKS_PER_SECOND: u64 = 3;

const W: u64 = HISTORY_PROOF_WINDOW_SIZE as u64;

/// Which layer's root the dense chain ends at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorLayerMode {
    /// Exactly this layer: the contract's `layerNumber`, 1 = the block tree.
    Explicit(u32),
    /// The highest layer whose anchor block the chain has already produced.
    Auto,
}

impl Default for AnchorLayerMode {
    fn default() -> Self {
        Self::Explicit(1)
    }
}

impl AnchorLayerMode {
    /// Maps the legacy `max_layers` (chain steps above L1): `Some(n)` is layer
    /// `n + 1`, `None` is [`AnchorLayerMode::Auto`].
    pub fn from_max_layers(max_layers: Option<u32>) -> Self {
        match max_layers {
            Some(steps) => Self::Explicit(steps.saturating_add(1)),
            None => Self::Auto,
        }
    }
}

impl FromStr for AnchorLayerMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        if s.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        let layer: u32 = s.parse().map_err(|_| {
            anyhow::anyhow!("anchor layer must be 1..={MAX_ANCHOR_LAYER} or `auto`, got `{s}`")
        })?;
        validate_layer(layer)?;
        Ok(Self::Explicit(layer))
    }
}

impl fmt::Display for AnchorLayerMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Explicit(layer) => write!(f, "{layer}"),
            Self::Auto => f.write_str("auto"),
        }
    }
}

pub fn validate_layer(layer: u32) -> anyhow::Result<()> {
    anyhow::ensure!(
        (1..=MAX_ANCHOR_LAYER).contains(&layer),
        "anchor layer must be in 1..={MAX_ANCHOR_LAYER}, got {layer}"
    );
    Ok(())
}

/// How long to poll for an anchor block that does not exist yet.
#[derive(Clone, Copy, Debug)]
pub struct WaitOptions {
    pub timeout: Duration,
    pub poll_interval: Duration,
}

/// Anchor settings for [`crate::make_private_witness_with_anchor`].
#[derive(Clone, Copy, Debug, Default)]
pub struct AnchorOptions {
    pub layer: AnchorLayerMode,
    /// `None`: fail at once if the anchor block has not been produced yet.
    pub wait: Option<WaitOptions>,
    /// Write the fixture even if the node has already evicted the root. Only
    /// for offline fixtures: the chain rejects such a proof.
    pub allow_expired: bool,
}

fn stride(layer: u32) -> Option<u64> {
    W.checked_pow(layer)
}

/// `T_n`: height of the block that publishes the layer-`layer` root covering
/// `height`. `None` if it does not fit in `u64`.
pub fn anchor_block_height(height: u64, layer: u32) -> Option<u64> {
    let stride = stride(layer)?;
    (height / stride * stride).checked_add(stride)
}

/// `E_n`: height of the first block whose history cursor no longer holds that
/// root; once it exists, a new transaction can no longer use the root. `None`
/// if it does not fit in `u64`.
pub fn anchor_expiry_height(height: u64, layer: u32) -> Option<u64> {
    anchor_block_height(height, layer.checked_add(1)?)?.checked_add(stride(layer)?)
}

/// Leaf position of the layer-`lower` root covering `height` inside the
/// layer-(`lower` + 1) tree. The tree's leaves are `[higher-layer root,
/// previous same-layer root, W data roots]`, the data roots in height order,
/// so the root from block `T_lower` sits at `1 + (T_lower - cursor) / W^lower`.
pub fn rung_position(height: u64, lower: u32) -> Option<usize> {
    let stride = stride(lower)?;
    let window = stride.checked_mul(W)?;
    let cursor = height / window * window;
    let index = (anchor_block_height(height, lower)? - cursor) / stride;
    Some(1 + index as usize)
}

/// Rough wall-clock time for `blocks` blocks at [`NOMINAL_BLOCKS_PER_SECOND`].
pub fn approx_duration(blocks: u64) -> String {
    let secs = blocks.div_ceil(NOMINAL_BLOCKS_PER_SECOND);
    match secs {
        0..=119 => format!("~{secs} s"),
        120..=7_199 => format!("~{} min", (secs + 30) / 60),
        7_200..=172_799 => format!("~{} h", (secs + 1_800) / 3_600),
        _ => format!("~{} days", (secs + 43_200) / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_block_is_the_next_multiple_strictly_above_the_event() {
        for (height, layer, expected) in [
            (0, 1, W),
            (7, 1, W),
            (W - 1, 1, W),
            // A root published exactly at the event height covers the previous window.
            (W, 1, 2 * W),
            (W * W - 1, 1, W * W),
            (W * W, 1, W * W + W),
            (0, 2, W * W),
            (W * W - 1, 2, W * W),
            (W * W, 2, 2 * W * W),
            (7, 3, W * W * W),
        ] {
            assert_eq!(anchor_block_height(height, layer), Some(expected), "h={height} n={layer}");
        }
    }

    #[test]
    fn expiry_is_one_lower_stride_after_the_next_layer_boundary() {
        for (height, layer, expected) in [
            (7, 1, W * W + W),
            // Last L1 window before an L2 boundary: the L1 root lives only W blocks.
            (W * W - 1, 1, W * W + W),
            (W * W, 1, 2 * W * W + W),
            (7, 2, W * W * W + W * W),
        ] {
            assert_eq!(anchor_expiry_height(height, layer), Some(expected), "h={height} n={layer}");
        }
    }

    #[test]
    fn root_lifetime_is_between_one_and_w_lower_strides() {
        for height in [0, 1, 127, 128, 129, 16_000, 16_255, 16_256, 16_383, 16_384, 1_000_000] {
            for layer in 1..=2 {
                let life = anchor_expiry_height(height, layer).unwrap()
                    - anchor_block_height(height, layer).unwrap();
                let stride = W.pow(layer);
                assert!((stride..=stride * W).contains(&life), "h={height} n={layer}: {life}");
            }
        }
    }

    #[test]
    fn rung_position_points_at_the_lower_root_in_height_order() {
        for (height, lower, expected) in [
            (7, 1, 2),
            (W, 1, 3),
            // T_1 == T_2: the last data leaf.
            (W * W - 1, 1, W as usize + 1),
            (W * W, 1, 2),
            (7, 2, 2),
        ] {
            assert_eq!(rung_position(height, lower), Some(expected), "h={height} lower={lower}");
        }
    }

    #[test]
    fn rung_position_matches_the_layer_n_data_layout() {
        // `get_layer_n_data(h, m)` lists the layer-m roots published at
        // `cursor + k·W^m`, k = 1..=W, after the two header leaves.
        for height in [0, 7, 127, 128, 16_383, 16_384, 16_511, 2_097_151, 2_097_152, 5_000_000] {
            for lower in 1..=3 {
                let stride = W.pow(lower);
                let cursor = height / (stride * W) * (stride * W);
                let position = rung_position(height, lower).unwrap();
                assert!((2..=W as usize + 1).contains(&position));
                assert_eq!(
                    cursor + (position as u64 - 1) * stride,
                    anchor_block_height(height, lower).unwrap(),
                    "h={height} lower={lower}"
                );
            }
        }
    }

    #[test]
    fn unreachable_layers_do_not_overflow() {
        // W^10 = 2^70 does not fit in u64.
        assert_eq!(anchor_block_height(7, 10), None);
        assert_eq!(anchor_expiry_height(7, 9), None);
        assert_eq!(rung_position(7, 9), None);
    }

    #[test]
    fn parses_layers_and_auto() {
        assert_eq!("1".parse::<AnchorLayerMode>().unwrap(), AnchorLayerMode::Explicit(1));
        assert_eq!("12".parse::<AnchorLayerMode>().unwrap(), AnchorLayerMode::Explicit(12));
        assert_eq!("auto".parse::<AnchorLayerMode>().unwrap(), AnchorLayerMode::Auto);
        assert_eq!("AUTO".parse::<AnchorLayerMode>().unwrap(), AnchorLayerMode::Auto);
        for bad in ["0", "13", "-1", "", "L2", "1.5"] {
            assert!(bad.parse::<AnchorLayerMode>().is_err(), "`{bad}` must be rejected");
        }
    }

    #[test]
    fn legacy_max_layers_maps_to_layers() {
        assert_eq!(AnchorLayerMode::from_max_layers(None), AnchorLayerMode::Auto);
        assert_eq!(AnchorLayerMode::from_max_layers(Some(0)), AnchorLayerMode::Explicit(1));
        assert_eq!(AnchorLayerMode::from_max_layers(Some(1)), AnchorLayerMode::Explicit(2));
        assert_eq!(AnchorLayerMode::default(), AnchorLayerMode::Explicit(1));
    }

    #[test]
    fn approx_duration_matches_the_documented_windows() {
        assert_eq!(approx_duration(W), "~43 s");
        assert_eq!(approx_duration(W * W), "~91 min");
        assert_eq!(approx_duration(W * W * W), "~8 days");
    }
}
