function dilithium_aes256ctr_init(state, key, nonce) {
  let expnonce = new Uint8Array(12);
  expnonce[0] = nonce;
  expnonce[1] = nonce >> 8;
  aes256ctr_init(state, key, expnonce);
}