function poly_reduce(a) {
  let i;
  DBENCH_START();

  for (i = 0; i < N; ++i) {
    a.coeffs[i] = reduce32(a.coeffs[i]);
  }

  DBENCH_STOP(tred);
}

function poly_caddq(a) {
  let i;
  DBENCH_START();

  for(i = 0; i < N; ++i)
    a.coeffs[i] = caddq(a.coeffs[i]);

  DBENCH_STOP(tred);
}

function poly_add(c, a, b) {
  let i;
  DBENCH_START();

  for (i = 0; i < N; ++i) {
    c.coeffs[i] = a.coeffs[i] + b.coeffs[i];
  }

  DBENCH_STOP(tadd);
}

function poly_sub(c, a, b) {
  let i;
  DBENCH_START();

  for (i = 0; i < N; ++i)
    c.coeffs[i] = a.coeffs[i] - b.coeffs[i];

  DBENCH_STOP(tadd);
}


function poly_shiftl(a) {
  const D = 1 << R;
  for (let i = 0; i < N; ++i) {
    a.coeffs[i] <<= D;
  }
  DBENCH_STOP(tmul);
}

function poly_invntt_tomont(a) {
  DBENCH_START();

  invntt_tomont(a.coeffs);

  DBENCH_STOP(tmul);
}

function poly_pointwise_montgomery(c, a, b) {
  DBENCH_START();

  for (let i = 0; i < N; ++i) {
    c.coeffs[i] = montgomery_reduce((BigInt(a.coeffs[i]) * BigInt(b.coeffs[i])) % q);
  }

  DBENCH_STOP(tmul);
}

function poly_power2round(a1, a0, a) {
  let i;
  DBENCH_START();

  for(i = 0; i < N; ++i) {
    a1.coeffs[i] = power2round(a0.coeffs[i], a.coeffs[i]);
  }

  DBENCH_STOP(tround);
}

function poly_make_hint(h, a0, a1) {
  let s = 0;
  for (let i = 0; i < N; i++) {
    h.coeffs[i] = make_hint(a0.coeffs[i], a1.coeffs[i]);
    s += h.coeffs[i];
  }
  DBENCH_STOP(tround);
  return s;
}

function poly_use_hint(b, a, h) {
  let i;
  DBENCH_START();

  for(i = 0; i < N; ++i)
    b.coeffs[i] = use_hint(a.coeffs[i], h.coeffs[i]);

  DBENCH_STOP(tround);
}


function poly_chknorm(a, B) {
  let i;
  let t;
  DBENCH_START();

  if (B > (Q - 1) / 8) {
    return 1;
  }

  for (i = 0; i < N; ++i) {
    /* Absolute value */
    t = a.coeffs[i] >> 31;
    t = a.coeffs[i] - (t & (2 * a.coeffs[i]));

    if (t >= B) {
      DBENCH_STOP(tsample);
      return 1;
    }
  }

  DBENCH_STOP(tsample); // 性能测量的宏定义
  return 0;
}


function rej_uniform(a, len, buf, buflen) {
  let ctr = 0, pos = 0;
  let t;
  DBENCH_START();

  while (ctr < len && pos + 3 <= buflen) {
    t = buf[pos++];
    t |= buf[pos++] << 8;
    t |= buf[pos++] << 16;
    t &= 0x7FFFFF;

    if (t < Q) {
      a[ctr++] = t;
    }
  }

  DBENCH_STOP(tsample);
  return ctr;
}


const POLY_UNIFORM_ETA_NBLOCKS = (ETA === 2) ? ((136 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES) : ((227 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES);

function poly_uniform_eta(a, seed, nonce) {
  let ctr = 0;
  const buflen = POLY_UNIFORM_ETA_NBLOCKS*STREAM256_BLOCKBYTES;
  const buf = new Uint8Array(buflen);
  const state = new stream256_state();

  stream256_init(state, seed, nonce);
  stream256_squeezeblocks(buf, POLY_UNIFORM_ETA_NBLOCKS, state);

  ctr = rej_eta(a.coeffs, N, buf, buflen);

  while(ctr < N) {
    stream256_squeezeblocks(buf, 1, state);
    ctr += rej_eta(a.coeffs.subarray(ctr), N - ctr, buf, STREAM256_BLOCKBYTES);
  }
}

const POLY_UNIFORM_GAMMA1_NBLOCKS = Math.ceil(POLYZ_PACKEDBYTES / STREAM256_BLOCKBYTES);
function poly_uniform_gamma1(a, seed, nonce) {
  const buf = new Uint8Array(POLY_UNIFORM_GAMMA1_NBLOCKS * STREAM256_BLOCKBYTES);
  const state = new stream256_state();

  stream256_init(state, seed, nonce);
  stream256_squeezeblocks(buf, POLY_UNIFORM_GAMMA1_NBLOCKS, state);
  polyz_unpack(a, buf);
}


function poly_challenge(c, seed) {
  const buf = new Uint8Array(SHAKE256_RATE);
  const state = new Keccak(SHAKE256_RATE * 8, SEEDBYTES * 8);

  state.absorb(seed, SEEDBYTES * 8);
  state.squeeze(buf, SHAKE256_RATE * 8);

  let signs = 0;
  for (let i = 0; i < 8; ++i) {
    signs |= BigInt(buf[i]) << BigInt(8 * i);
  }
  let pos = 8;

  c.coeffs.fill(0);
  for (let i = N - TAU; i < N; ++i) {
    let b;
    do {
      if (pos >= SHAKE256_RATE) {
        state.squeeze(buf, SHAKE256_RATE * 8);
        pos = 0;
      }
      b = buf[pos++];
    } while (b > i);

    c.coeffs[i] = c.coeffs[b];
    c.coeffs[b] = 1n - 2n * (signs & 1n);
    signs >>= 1n;
  }
}

function polyeta_pack(r, a) {
  var i;
  var t = new Array(8);
  
  // DBENCH_START(); (Assuming it is a macro/function defined elsewhere)
  
  if (ETA == 2) {
    for(i = 0; i < N/8; ++i) {
      t[0] = ETA - a.coeffs[8*i+0];
      t[1] = ETA - a.coeffs[8*i+1];
      t[2] = ETA - a.coeffs[8*i+2];
      t[3] = ETA - a.coeffs[8*i+3];
      t[4] = ETA - a.coeffs[8*i+4];
      t[5] = ETA - a.coeffs[8*i+5];
      t[6] = ETA - a.coeffs[8*i+6];
      t[7] = ETA - a.coeffs[8*i+7];
  
      r[3*i+0]  = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
      r[3*i+1]  = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
      r[3*i+2]  = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
    }
  }
  else if (ETA == 4) {
    for(i = 0; i < N/2; ++i) {
      t[0] = ETA - a.coeffs[2*i+0];
      t[1] = ETA - a.coeffs[2*i+1];
      r[i] = t[0] | (t[1] << 4);
    }
  }
  
  // DBENCH_STOP(*tpack); (Assuming it is a macro/function defined elsewhere)
}


function polyeta_unpack(r, a) {
  let i;

  // unpack eta
  const ETA_MINUS_ONE = ETA - 1;
  
  if (ETA === 2) {
    for(i = 0; i < N/8; ++i) {
      r.coeffs[8*i+0] = (a[3*i+0] >> 0) & 7;
      r.coeffs[8*i+1] = (a[3*i+0] >> 3) & 7;
      r.coeffs[8*i+2] = ((a[3*i+0] >> 6) | (a[3*i+1] << 2)) & 7;
      r.coeffs[8*i+3] = (a[3*i+1] >> 1) & 7;
      r.coeffs[8*i+4] = (a[3*i+1] >> 4) & 7;
      r.coeffs[8*i+5] = ((a[3*i+1] >> 7) | (a[3*i+2] << 1)) & 7;
      r.coeffs[8*i+6] = (a[3*i+2] >> 2) & 7;
      r.coeffs[8*i+7] = (a[3*i+2] >> 5) & 7;

      r.coeffs[8*i+0] = ETA_MINUS_ONE - r.coeffs[8*i+0];
      r.coeffs[8*i+1] = ETA_MINUS_ONE - r.coeffs[8*i+1];
      r.coeffs[8*i+2] = ETA_MINUS_ONE - r.coeffs[8*i+2];
      r.coeffs[8*i+3] = ETA_MINUS_ONE - r.coeffs[8*i+3];
      r.coeffs[8*i+4] = ETA_MINUS_ONE - r.coeffs[8*i+4];
      r.coeffs[8*i+5] = ETA_MINUS_ONE - r.coeffs[8*i+5];
      r.coeffs[8*i+6] = ETA_MINUS_ONE - r.coeffs[8*i+6];
      r.coeffs[8*i+7] = ETA_MINUS_ONE - r.coeffs[8*i+7];
    }
  }
  else if (ETA === 4) {
    for(i = 0; i < N/2; ++i) {
      r.coeffs[2*i+0] = a[i] & 0x0F;
      r.coeffs[2*i+1] = a[i] >> 4;
      r.coeffs[2*i+0] = ETA_MINUS_ONE - r.coeffs[2*i+0];
      r.coeffs[2*i+1] = ETA_MINUS_ONE - r.coeffs[2*i+1];
    }
  }
  // #endif
  DBENCH_STOP(tpack);
}

function polyt1_pack(r, a) {
  let i;
  DBENCH_START();

  for(i = 0; i < N/4; ++i) {
    r[5*i+0] = (a.coeffs[4*i+0] >>> 0) & 0xFF;
    r[5*i+1] = (a.coeffs[4*i+0] >>> 8) & 0xFF | (a.coeffs[4*i+1] << 2) & 0xFF;
    r[5*i+2] = (a.coeffs[4*i+1] >>> 6) & 0xFF | (a.coeffs[4*i+2] << 4) & 0xFF;
    r[5*i+3] = (a.coeffs[4*i+2] >>> 4) & 0xFF | (a.coeffs[4*i+3] << 6) & 0xFF;
    r[5*i+4] = (a.coeffs[4*i+3] >>> 2) & 0xFF;
  }

  DBENCH_STOP(tpack);
}


function polyt1_unpack(r, a) {
  let i;
  DBENCH_START();

  for (i = 0; i < N/4; ++i) {
    r.coeffs[4*i+0] = ((a[5*i+0] >> 0) | (a[5*i+1] << 8)) & 0x3FF;
    r.coeffs[4*i+1] = ((a[5*i+1] >> 2) | (a[5*i+2] << 6)) & 0x3FF;
    r.coeffs[4*i+2] = ((a[5*i+2] >> 4) | (a[5*i+3] << 4)) & 0x3FF;
    r.coeffs[4*i+3] = ((a[5*i+3] >> 6) | (a[5*i+4] << 2)) & 0x3FF;
  }

  DBENCH_STOP(tpack);
}


function polyt0_pack(r, a) {
  let i;
  const t = new Uint32Array(8);
  DBENCH_START();

  for (i = 0; i < N / 8; ++i) {
    t[0] = (1 << (D - 1)) - a.coeffs[8 * i + 0];
    t[1] = (1 << (D - 1)) - a.coeffs[8 * i + 1];
    t[2] = (1 << (D - 1)) - a.coeffs[8 * i + 2];
    t[3] = (1 << (D - 1)) - a.coeffs[8 * i + 3];
    t[4] = (1 << (D - 1)) - a.coeffs[8 * i + 4];
    t[5] = (1 << (D - 1)) - a.coeffs[8 * i + 5];
    t[6] = (1 << (D - 1)) - a.coeffs[8 * i + 6];
    t[7] = (1 << (D - 1)) - a.coeffs[8 * i + 7];

    r[13 * i + 0] = t[0];
    r[13 * i + 1] = t[0] >> 8;
    r[13 * i + 1] |= t[1] << 5;
    r[13 * i + 2] = t[1] >> 3;
    r[13 * i + 3] = t[1] >> 11;
    r[13 * i + 3] |= t[2] << 2;
    r[13 * i + 4] = t[2] >> 6;
    r[13 * i + 4] |= t[3] << 7;
    r[13 * i + 5] = t[3] >> 1;
    r[13 * i + 6] = t[3] >> 9;
    r[13 * i + 6] |= t[4] << 4;
    r[13 * i + 7] = t[4] >> 4;
    r[13 * i + 8] = t[4] >> 12;
    r[13 * i + 8] |= t[5] << 1;
    r[13 * i + 9] = t[5] >> 7;
    r[13 * i + 9] |= t[6] << 6;
    r[13 * i + 10] = t[6] >> 2;
    r[13 * i + 11] = t[6] >> 10;
    r[13 * i + 11] |= t[7] << 3;
    r[13 * i + 12] = t[7] >> 5;
  }

  DBENCH_STOP(tpack);
}


function polyt0_unpack(r, a) {
  let i;
  DBENCH_START();

  for (i = 0; i < N / 8; ++i) {
    r.coeffs[8 * i + 0] = a[13 * i + 0];
    r.coeffs[8 * i + 0] |= (a[13 * i + 1] << 8) >>> 0;
    r.coeffs[8 * i + 0] &= 0x1fff;

    r.coeffs[8 * i + 1] = a[13 * i + 1] >>> 5;
    r.coeffs[8 * i + 1] |= (a[13 * i + 2] << 3) >>> 0;
    r.coeffs[8 * i + 1] |= (a[13 * i + 3] << 11) >>> 0;
    r.coeffs[8 * i + 1] &= 0x1fff;

    r.coeffs[8 * i + 2] = a[13 * i + 3] >>> 2;
    r.coeffs[8 * i + 2] |= (a[13 * i + 4] << 6) >>> 0;
    r.coeffs[8 * i + 2] &= 0x1fff;

    r.coeffs[8 * i + 3] = a[13 * i + 4] >>> 7;
    r.coeffs[8 * i + 3] |= (a[13 * i + 5] << 1) >>> 0;
    r.coeffs[8 * i + 3] |= (a[13 * i + 6] << 9) >>> 0;
    r.coeffs[8 * i + 3] &= 0x1fff;

    r.coeffs[8 * i + 4] = a[13 * i + 6] >>> 4;
    r.coeffs[8 * i + 4] |= (a[13 * i + 7] << 4) >>> 0;
    r.coeffs[8 * i + 4] |= (a[13 * i + 8] << 12) >>> 0;
    r.coeffs[8 * i + 4] &= 0x1fff;

    r.coeffs[8 * i + 5] = a[13 * i + 8] >>> 1;
    r.coeffs[8 * i + 5] |= (a[13 * i + 9] << 7) >>> 0;
    r.coeffs[8 * i + 5] &= 0x1fff;

    r.coeffs[8 * i + 6] = a[13 * i + 9] >>> 6;
    r.coeffs[8 * i + 6] |= (a[13 * i + 10] << 2) >>> 0;
    r.coeffs[8 * i + 6] |= (a[13 * i + 11] << 10) >>> 0;
    r.coeffs[8 * i + 6] &= 0x1fff;

    r.coeffs[8 * i + 7] = a[13 * i + 11] >>> 3;
    r.coeffs[8 * i + 7] |= (a[13 * i + 12] << 5) >>> 0;
    r.coeffs[8 * i + 7] &= 0x1fff;
    for (let j = 0; j < 8; j++) {
      r.coeffs[8*i+j] = (1 << (D-1)) - r.coeffs[8*i+j];
    }
  DBENCH_STOP(tpack);
}


function polyz_pack(r, a) {
  const t = new Uint32Array(4);
  const N_DIV_4 = N / 4;
  const N_DIV_2 = N / 2;
  //DBENCH_START();
  performance.mark("start");

  if (GAMMA1 === 1 << 17) {
    for (let i = 0; i < N_DIV_4; i++) {
      t[0] = GAMMA1 - a.coeffs[4 * i + 0];
      t[1] = GAMMA1 - a.coeffs[4 * i + 1];
      t[2] = GAMMA1 - a.coeffs[4 * i + 2];
      t[3] = GAMMA1 - a.coeffs[4 * i + 3];

      r[9 * i + 0] = t[0];
      r[9 * i + 1] = t[0] >> 8;
      r[9 * i + 2] = t[0] >> 16;
      r[9 * i + 2] |= t[1] << 2;
      r[9 * i + 3] = t[1] >> 6;
      r[9 * i + 4] = t[1] >> 14;
      r[9 * i + 4] |= t[2] << 4;
      r[9 * i + 5] = t[2] >> 4;
      r[9 * i + 6] = t[2] >> 12;
      r[9 * i + 6] |= t[3] << 6;
      r[9 * i + 7] = t[3] >> 2;
      r[9 * i + 8] = t[3] >> 10;
    }
  } else if (GAMMA1 === 1 << 19) {
    for (let i = 0; i < N_DIV_2; i++) {
      t[0] = GAMMA1 - a.coeffs[2 * i + 0];
      t[1] = GAMMA1 - a.coeffs[2 * i + 1];

      r[5 * i + 0] = t[0];
      r[5 * i + 1] = t[0] >> 8;
      r[5 * i + 2] = t[0] >> 16;
      r[5 * i + 2] |= t[1] << 4;
      r[5 * i + 3] = t[1] >> 4;
      r[5 * i + 4] = t[1] >> 12;
    }
  }
  DBENCH_STOP(tpack);
  // performance.mark("stop");
  // performance.measure("polyz_pack", "start", "stop");
}


function polyz_unpack(r, a) {
  let i;
  DBENCH_START();

  if (GAMMA1 === Math.pow(2, 17)) {
    for (i = 0; i < N / 4; ++i) {
      r.coeffs[4 * i + 0] = a[9 * i + 0];
      r.coeffs[4 * i + 0] |= (a[9 * i + 1] << 8);
      r.coeffs[4 * i + 0] |= (a[9 * i + 2] << 16);
      r.coeffs[4 * i + 0] &= 0x3FFFF;

      r.coeffs[4 * i + 1] = a[9 * i + 2] >> 2;
      r.coeffs[4 * i + 1] |= (a[9 * i + 3] << 6);
      r.coeffs[4 * i + 1] |= (a[9 * i + 4] << 14);
      r.coeffs[4 * i + 1] &= 0x3FFFF;

      r.coeffs[4 * i + 2] = a[9 * i + 4] >> 4;
      r.coeffs[4 * i + 2] |= (a[9 * i + 5] << 4);
      r.coeffs[4 * i + 2] |= (a[9 * i + 6] << 12);
      r.coeffs[4 * i + 2] &= 0x3FFFF;

      r.coeffs[4 * i + 3] = a[9 * i + 6] >> 6;
      r.coeffs[4 * i + 3] |= (a[9 * i + 7] << 2);
      r.coeffs[4 * i + 3] |= (a[9 * i + 8] << 10);
      r.coeffs[4 * i + 3] &= 0x3FFFF;

      r.coeffs[4 * i + 0] = GAMMA1 - r.coeffs[4 * i + 0];
      r.coeffs[4 * i + 1] = GAMMA1 - r.coeffs[4 * i + 1];
      r.coeffs[4 * i + 2] = GAMMA1 - r.coeffs[4 * i + 2];
      r.coeffs[4 * i + 3] = GAMMA1 - r.coeffs[4 * i + 3];
    }
  } else if (GAMMA1 === Math.pow(2, 19)) {
    for (i = 0; i < N / 2; ++i) {
      r.coeffs[2 * i + 0] = a[5 * i + 0];
      r.coeffs[2 * i + 0] |= (a[5 * i + 1] << 8);
      r.coeffs[2 * i + 0] |= (a[5 * i + 2] << 16);
      r.coeffs[2 * i + 0] &= 0xFFFFF;

      r.coeffs[2 * i + 1] = a[5 * i + 2] >> 4;
      r.coeffs[2 * i + 1] |= (a[5 * i + 3] << 4);
      r.coeffs[2 * i + 1] |= (a[5 * i + 4] << 12);
      r.coeffs[2 * i + 0] &= 0xFFFFF;
      r.coeffs[2 * i + 0] = GAMMA1 - r.coeffs[2 * i + 0];
      r.coeffs[2 * i + 1] = GAMMA1 - r.coeffs[2 * i + 1];
    }
    
  }
  DBENCH_STOP(tpack);
}

function polyw1_pack(r, a) {
  let i;
  DBENCH_START();

  const div = GAMMA2 === (Q - 1) / 88 ? 4 : 2;

  if (div === 4) {
    for (i = 0; i < N / div; ++i) {
      r[3 * i + 0] = a.coeffs[4 * i + 0];
      r[3 * i + 0] |= a.coeffs[4 * i + 1] << 6;
      r[3 * i + 1] = a.coeffs[4 * i + 1] >> 2;
      r[3 * i + 1] |= a.coeffs[4 * i + 2] << 4;
      r[3 * i + 2] = a.coeffs[4 * i + 2] >> 4;
      r[3 * i + 2] |= a.coeffs[4 * i + 3] << 2;
    }
  } else if (div === 2) {
    for (i = 0; i < N / div; ++i) {
      r[i] = a.coeffs[2 * i + 0] | (a.coeffs[2 * i + 1] << 4);
    }
  }

  DBENCH_STOP(tpack);
}
