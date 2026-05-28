use halo2_base::halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Error, TableColumn},
};
use halo2_base::utils::BigPrimeField;

/// Fills a lookup table column with every byte value [0, 255].
///
/// The table must have been declared via `meta.lookup_table_column()` in
/// `configure`.  Pass the column and a mutable reference to the layouter;
/// the function will call `layouter.assign_table` once and return any error.
pub fn fill_byte_range_table<F: BigPrimeField>(
    layouter: &mut impl Layouter<F>,
    byte_table: TableColumn,
) -> Result<(), Error> {
    layouter.assign_table(
        || "byte_range_table",
        |mut table| {
            for i in 0u64..256 {
                table.assign_cell(
                    || "byte",
                    byte_table,
                    i as usize,
                    || Value::known(F::from(i)),
                )?;
            }
            Ok(())
        },
    )
}

/// Computes the SHA-256 padded message for a given input.
///
/// Follows the standard: append bit `1`, then zeros, then 64-bit big-endian
/// bit-length, so that the total length is a multiple of 64 bytes.
pub fn sha256_pad(data: &[u8]) -> Vec<u8> {
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    padded
}
