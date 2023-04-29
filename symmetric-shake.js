function dilithium_shake128_stream_init(state, seed, nonce) {
  let t = new Uint8Array(2);
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake128_init(state);
  shake128_absorb(state, seed, SEEDBYTES);
  shake128_absorb(state, t, 2);
  shake128_finalize(state);
}

function dilithium_shake256_stream_init(state, seed, nonce) {
  let t = new Uint8Array(2);
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake256_init(state);
  shake256_absorb(state, seed, CRHBYTES);
  shake256_absorb(state, t, 2);
  shake256_finalize(state);
}