const { randomBytes } = require('crypto');
const { shake256 } = require('js-sha3');
const { SEEDBYTES, CRHBYTES, L, CRYPTO_PUBLICKEYBYTES } = require('./params');
const { polyvec_matrix_expand, polyvecl_uniform_eta, polyveck_uniform_eta, polyvecl_ntt, polyvec_matrix_pointwise_montgomery, polyveck_reduce, polyveck_invntt_tomont, polyveck_caddq, polyveck_power2round } = require('./polyvec');
const { pack_pk, pack_sk } = require('./packing');

function crypto_sign_keypair(pk, sk) {
  const seedbuf = Buffer.alloc(2 * SEEDBYTES + CRHBYTES);
  const tr = Buffer.alloc(SEEDBYTES);
  let rho, rhoprime, key;
  const mat = [];
  const s1 = { vec: [] };
  const s1hat = { vec: [] };
  const s2 = { vec: [] };
  const t1 = { vec: [] };
  const t0 = { vec: [] };

  /* Get randomness for rho, rhoprime and key */
  randomBytes(seedbuf);
  shake256(seedbuf, seedbuf, SEEDBYTES, 2 * SEEDBYTES + CRHBYTES);
  rho = seedbuf.slice(0, SEEDBYTES);
  rhoprime = seedbuf.slice(SEEDBYTES, SEEDBYTES + CRHBYTES);
  key = seedbuf.slice(SEEDBYTES + CRHBYTES, 2 * SEEDBYTES + CRHBYTES);

  /* Expand matrix */
  polyvec_matrix_expand(mat, rho);

  /* Sample short vectors s1 and s2 */
  polyvecl_uniform_eta(s1, rhoprime, 0);
  polyveck_uniform_eta(s2, rhoprime, L);

  /* Matrix-vector multiplication */
  s1hat.vec = [...s1.vec];
  polyvecl_ntt(s1hat);
  polyvec_matrix_pointwise_montgomery(t1, mat, s1hat);
  polyveck_reduce(t1);
  polyveck_invntt_tomont(t1);

  /* Add error vector s2 */
  polyveck_add(t1, t1, s2);

  /* Extract t1 and write public key */
  polyveck_caddq(t1);
  polyveck_power2round(t1, t0, t1);
  pack_pk(pk, rho, t1);

  /* Compute H(rho, t1) and write secret key */
  shake256(tr, CRYPTO_PUBLICKEYBYTES, pk, SEEDBYTES);
  pack_sk(sk, rho, tr, key, t0, s1, s2);

  return 0;
}


function crypto_sign_signature(sig, siglen, m, mlen, sk) {
  let n;
  const seedbuf = new Uint8Array(3 * SEEDBYTES + 2 * CRHBYTES);
  let rho, tr, key, mu, rhoprime;
  let nonce = 0;
  const mat = new Array(K);
  for (let i = 0; i < K; i++) {
    mat[i] = new polyvec();
  }
  const s1 = new polyvecl();
  const y = new polyvecl();
  const z = new polyvecl();
  const t0 = new polyveck();
  const s2 = new polyveck();
  const w1 = new polyveck();
  const w0 = new polyveck();
  const h = new polyveck();
  const cp = new poly();
  const state = new sha3.keccak256();

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + SEEDBYTES;
  mu = key + SEEDBYTES;
  rhoprime = mu + CRHBYTES;
  unpack_sk(rho, tr, key, t0, s1, s2, sk);

  /* Compute CRH(tr, msg) */
  state.reset();
  state.append(tr, SEEDBYTES);
  state.append(m, mlen);
  const muBytes = state.digest(CRHBYTES);
  mu.set(muBytes);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
  randombytes(rhoprime, CRHBYTES);
#else
  shake256(rhoprime, CRHBYTES, key, SEEDBYTES + CRHBYTES);
#endif

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);
  s1.ntt();
  s2.ntt();
  t0.ntt();

rej:
  /* Sample intermediate vector y */
  polyvecl_uniform_gamma1(y, rhoprime, nonce++);

  /* Matrix-vector multiplication */
  z.copy(y);
  z.ntt();
  polyvec_matrix_pointwise_montgomery(w1, mat, z);
  w1.reduce();
  w1.invntt();

  /* Decompose w and call the random oracle */
  w1.caddq();
  polyveck_decompose(w1, w0, w1);
  polyveck_pack_w1(sig, w1);

  state.reset();
  state.append(mu, CRHBYTES);
  state.append(sig, K * POLYW1_PACKEDBYTES);
  const sigBytes = state.digest(SEEDBYTES);
  sig.set(sigBytes);

  poly_challenge(cp, sig);
  cp.ntt();

  /* Compute z, reject if it reveals secret */
  polyvecl_pointwise_poly_montgomery(z, cp, s1);
  z.invntt();
  polyvecl_add(z, z, y);
  z.reduce();
  if (polyvecl_chknorm(z, GAMMA1 - BETA)) {
    goto rej;
  }

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  polyveck_pointwise_poly_montgomery(h, cp, s2);
  h.invntt();
  polyveck_sub(w0, w0, h);
  w0.reduce();
  if (polyveck_chknorm(w0, GAMMA2 - BETA)) {
    goto rej;
  }

  // Compute hints for w1
  let h = new polyveck(K);
  polyveck_pointwise_poly_montgomery(h, cp, t0);
  polyveck_invntt_tomont(h);
  polyveck_reduce(h);
  if (polyveck_chknorm(h, GAMMA2)) {
    goto rej;
  }

  polyveck_add(w0, w0, h);
  let n = polyveck_make_hint(h, w0, w1);
  if (n > OMEGA) {
  goto rej;
  }

  // Write signature
  pack_sig(sig, sig, z, h);
  siglen = CRYPTO_BYTES;
  return 0;
}

function crypto_sign(sm, smlen, m, mlen, sk) {
  let i;
  for (i = 0; i < mlen; ++i) {
    sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
  }
  crypto_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, sk);
  *smlen += mlen;
  return 0;
}


function crypto_sign_verify(sig, siglen, m, mlen, pk) {
  const buf = new Uint8Array(K * POLYW1_PACKEDBYTES);
  const rho = new Uint8Array(SEEDBYTES);
  const mu = new Uint8Array(CRHBYTES);
  const c = new Uint8Array(SEEDBYTES);
  const c2 = new Uint8Array(SEEDBYTES);
  const cp = new Poly();
  const mat = Array.from({ length: K }, () => new PolyVec(L));
  const z = new PolyVec(L);
  const t1 = new PolyVec(K);
  const w1 = new PolyVec(K);
  const h = new PolyVec(K);
  const state = new Keccak();

  if (siglen !== CRYPTO_BYTES) return -1;

  unpack_pk(rho, t1, pk);
  if (unpack_sig(c, z, h, sig)) return -1;
  if (polyvecl_chknorm(z, GAMMA1 - BETA)) return -1;

  /* Compute CRH(H(rho, t1), msg) */
  shake256(mu, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  state.absorb(mu, SEEDBYTES);
  state.absorb(m, mlen);
  state.finalize();
  state.squeeze(mu, CRHBYTES);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(z);
  polyvec_matrix_pointwise_montgomery(w1, mat, z);

  poly_ntt(cp);
  polyveck_shiftl(t1);
  polyveck_ntt(t1);
  polyveck_pointwise_poly_montgomery(t1, cp, t1);

  polyveck_sub(w1, w1, t1);
  polyveck_reduce(w1);
  polyveck_invntt_tomont(w1);

  /* Reconstruct w1 */
  polyveck_caddq(w1);
  polyveck_use_hint(w1, w1, h);
  polyveck_pack_w1(buf, w1);

  /* Call random oracle and verify challenge */
  state.init();
  state.absorb(mu, CRHBYTES);
  state.absorb(buf, K * POLYW1_PACKEDBYTES);
  state.finalize();
  state.squeeze(c2, SEEDBYTES);
  for (let i = 0; i < SEEDBYTES; ++i)
    if (c[i] !== c2[i]) return -1;

  return 0;
}

function crypto_sign_open(m, mlen, sm, smlen, pk) {
  if (smlen < CRYPTO_BYTES) {
    return -1;
  }

  *mlen = smlen - CRYPTO_BYTES;

  if (crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, pk)) {
    *mlen = -1;
    for (let i = 0; i < smlen; ++i) {
      m[i] = 0;
    }
    return -1;
  } else {
    for (let i = 0; i < *mlen; ++i) {
      m[i] = sm[CRYPTO_BYTES + i];
    }
    return 0;
  }
}
