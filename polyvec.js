function polyvec_matrix_expand(mat, rho) {
  for(let i = 0; i < K; ++i) {
    for(let j = 0; j < L; ++j) {
      poly_uniform(mat[i].vec[j], rho, (i << 8) + j);
    }
  }
}

function polyvec_matrix_pointwise_montgomery(t, mat, v) {
  for(let i = 0; i < K; ++i) {
    polyvecl_pointwise_acc_montgomery(t.vec[i], mat[i], v);
  }
}

function polyvecl_uniform_eta(v, seed, nonce) {
  for(let i = 0; i < L; ++i) {
    poly_uniform_eta(v.vec[i], seed, nonce++);
  }
}

function polyvecl_uniform_gamma1(v, seed, nonce) {
  for(let i = 0; i < L; ++i) {
    poly_uniform_gamma1(v.vec[i], seed, L*nonce + i);
  }
}

function polyvecl_reduce(v) {
  for(let i = 0; i < L; ++i) {
    poly_reduce(v.vec[i]);
  }
}

function polyvecl_add(w, u, v) {
  for(let i = 0; i < L; ++i) {
    poly_add(w.vec[i], u.vec[i], v.vec[i]);
  }
}

function polyvecl_ntt(v) {
  for(let i = 0; i < L; ++i) {
    poly_ntt(v.vec[i]);
  }
}

function polyvecl_invntt_tomont(v) {
  for(let i = 0; i < L; ++i) {
    poly_invntt_tomont(v.vec[i]);
  }
}

function polyvecl_pointwise_poly_montgomery(r, a, v) {
  for(let i = 0; i < L; ++i) {
    poly_pointwise_montgomery(r.vec[i], a, v.vec[i]);
  }
}

function polyvecl_pointwise_acc_montgomery(w, u, v) {
  let t = new poly();
  poly_pointwise_montgomery(w, u.vec[0], v.vec[0]);
  for(let i = 1; i < L; ++i) {
    poly_pointwise_montgomery(t, u.vec[i], v.vec[i]);
    poly_add(w, w, t);
  }
}

function polyvecl_chknorm(v, bound) {
  for(let i = 0; i < L; ++i) {
    if(poly_chknorm(v.vec[i], bound)) {
      return 1;
    }
  }
  return 0;
}

function polyveck_uniform_eta(v, seed, nonce) {
  for(let i = 0; i < K; ++i) {
    poly_uniform_eta(v.vec[i], seed, nonce++);
  }
}

function polyveck_reduce(v) {
  for(let i = 0; i < K; ++i) {
    poly_reduce(v.vec[i]);
  }
}

function polyveck_caddq(v) {
  for(let i = 0; i < K; ++i) {
    poly_caddq(v.vec[i]);
  }
}

function polyveck_add(w, u, v) {
  for(let i = 0; i < K; ++i) {
    poly_add(w.vec[i], u.vec[i], v.vec[i]);
  }
}

function polyveck_sub(w, u, v) {
  for(let i = 0; i < K; ++i) {
    poly_sub(w.vec[i], u.vec[i], v.vec[i]);
  }
}

function polyveck_shiftl(v) {
  for(let i = 0; i < K; ++i) {
    poly_shiftl(v.vec[i]);
  }
}

function polyveck_ntt(v) {
  for(let i = 0; i < K; ++i) {
    poly_ntt(v.vec[i]);
  }
}

function polyveck_invntt_tomont(v) {
  for(let i = 0; i < K; ++i) {
    poly_invntt_tomont(v.vec[i]);
  }
}

function polyveck_pointwise_poly_montgomery(r, a, v) {
  for(let i = 0; i < K; ++i) {
    poly_pointwise_montgomery(r.vec[i], a, v.vec[i]);
  }
}

function polyveck_chknorm(v, bound) {
  for(let i = 0; i < K; ++i) {
    if(poly_chknorm(v.vec[i], bound)) {
      return 1;
    }
  }
  return 0;
}

function polyveck_power2round(v1, v0, v) {
  for(let i = 0; i < K; ++i) {
    poly_power2round(v1.vec[i], v0.vec[i], v.vec[i]);
  }
}

function polyveck_decompose(v1, v0, v) {
  for(let i = 0; i < K; ++i) {
    poly_decompose(v1.vec[i], v0.vec[i], v.vec[i]);
  }
}

function polyveck_make_hint(h, v0, v1) {
  let s = 0;
  for(let i = 0; i < K; ++i) {
    s += poly_make_hint(h.vec[i], v0.vec[i], v1.vec[i]);
  }
  return s;
}

function polyveck_use_hint(w, u, h) {
  for(let i = 0; i < K; ++i) {
    poly_use_hint(w.vec[i], u.vec[i], h.vec[i]);
  }
}

function polyveck_pack_w1(r, w1) {
  for(let i = 0; i < K; ++i) {
    polyw1_pack(r.slice(i*POLYW1_PACKEDBYTES, (i+1)*POLYW1_PACKEDBYTES), w1.vec[i]);
  }
}