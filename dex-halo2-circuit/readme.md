./tvm-cli decode msg --abi RootPN.abi.json event.boc

Input arguments:
     msg: event.boc
     abi: RootPN.abi.json
{
  "Type": "external outbound message",
  "Header": {
    "source": "0:1010101010101010101010101010101010101010101010101010101010101010",
    "destination": ":0000000000000000000000000000000000000000000000000000000000000087",
    "created_lt": "15574",
    "created_at": "1771860898"
  },
  "Body": "te6ccgEBAQEASgAAkGOAwhqrq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urqwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7msoAAAAAAg==",
  "BodyCall": {
    "voucherGenerated": {
      "sk_u_commit": "0xabababababababababababababababababababababababababababababababab",
      "voucher_nominal": "0x000000000000000000000000000000000000000000000000000000003b9aca00",
      "token_type": "2"
    }
  }
}


cargo test --release --package gosh-dark-dex-halo2-new-circuit --lib -- dark_dex_circuit_new::tests::test_dark_dex_circuit_real_proof --exact --nocapture --include-ignored