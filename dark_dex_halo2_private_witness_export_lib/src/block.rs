use base64::Engine;
use node_block_client::AckiNackiBlock;
use node_block_client::Envelope;

pub fn decode_envelope(base64_encoded_envelope: &str) -> anyhow::Result<Envelope<AckiNackiBlock>> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(base64_encoded_envelope)?;
    let block = bincode::deserialize::<Envelope<AckiNackiBlock>>(&bytes)?;
    Ok(block)
}
