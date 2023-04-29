function br_dec32le(src) {
  return (src[0] | (src[1] << 8) | (src[2] << 16) | (src[3] << 24)) >>> 0;
}

function br_range_dec32le(v, num, src) {
  while (num-- > 0) {
    v.push((src[0]) | (src[1] << 8) | (src[2] << 16) | (src[3] << 24));
    src = src.slice(4);
  }
}

function br_swap32(x) {
  x = ((x & 0x00FF00FF) << 8) | ((x >> 8) & 0x00FF00FF);
  return (x << 16) | (x >>> 16);
}

function br_enc32le(dst, x) {
  dst[0] = x & 0xff;
  dst[1] = (x >>> 8) & 0xff;
  dst[2] = (x >>> 16) & 0xff;
  dst[3] = (x >>> 24) & 0xff;
}


function br_range_enc32le(dst, v, num) {
  while (num-- > 0) {
    dst[0] = v & 0xff;
    dst[1] = (v >> 8) & 0xff;
    dst[2] = (v >> 16) & 0xff;
    dst[3] = (v >> 24) & 0xff;
    v++;
    dst += 4;
  }
}


function br_aes_ct64_bitslice_Sbox(q) {
  let x0, x1, x2, x3, x4, x5, x6, x7;
  let y1, y2, y3, y4, y5, y6, y7, y8, y9;
  let y10, y11, y12, y13, y14, y15, y16, y17, y18, y19;
  let y20, y21;
  let z0, z1, z2, z3, z4, z5, z6, z7, z8, z9;
  let z10, z11, z12, z13, z14, z15, z16, z17;
  let t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
  let t10, t11, t12, t13, t14, t15, t16, t17, t18, t19;
  let t20, t21, t22, t23, t24, t25, t26, t27, t28, t29;
  let t30, t31, t32, t33, t34, t35, t36, t37, t38, t39;
  let t40, t41, t42, t43, t44, t45, t46, t47, t48, t49;
  let t50, t51, t52, t53, t54, t55, t56, t57, t58, t59;
  let t60, t61, t62, t63, t64, t65, t66, t67;
  let s0, s1, s2, s3, s4, s5, s6, s7;

  x0 = q[7];
  x1 = q[6];
  x2 = q[5];
  x3 = q[4];
  x4 = q[3];
  x5 = q[2];
  x6 = q[1];
  x7 = q[0];

  y14 = x3 ^ x5;
  y13 = x0 ^ x6;
  y9 = x0 ^ x3;
  y8 = x0 ^ x5;
  t0 = x1 ^ x2;
  y1 = t0 ^ x7;
  y4 = y1 ^ x3;
  y12 = y13 ^ y14;
  y2 = y1 ^ x0;
  y5 = y1 ^ x6;
  y3 = y5 ^ y8;
  t1 = x4 ^ y12;
  y15 = t1 ^ x5;
  y20 = t1 ^ x1;
  y6 = y15 ^ x7;
  y10 = y15 ^ t0;
  y11 = y20 ^ y9;
  y7 = x7 ^ y11;
  y17 = y10 ^ y11;
  y19 = y10 ^ y8;
  y16 = t0 ^ y11;
  y21 = y13 ^ y16;
  y18 = x0 ^ y16;

  /*
   * Non-linear section.
   */
  t2 = y12 & y15;
  t3 = y3 & y6;
  t4 = t3 ^ t2;
  t5 = y4 & x7;
  t6 = t5 ^ t2;
  t7 = y13 & y16;
  t8 = y5 & y1;
  t9 = t8 ^ t7;
  t10 = y2 & y7;
  t11 = t10 ^ t7;
  t12 = y9 & y11;
  t13 = y14 & y17;
  t14 = t13 ^ t12;
  t15 = y8 & y10;
  t16 = t15 ^ t12;
  t17 = t4 ^ t14;
  t18 = t6 ^ t16;
  t19 = t9 ^ t14;
  t20 = t11 ^ t16;
  t21 = t17 ^ y20;
  t22 = t18 ^ y19;
  t23 = t19 ^ y21;
  t24 = t20 ^ y18;

  t25 = t21 ^ t22;
  t26 = t21 & t23;
  t27 = t24 ^ t26;
  t28 = t25 & t27;
  t29 = t28 ^ t22;
  t30 = t23 ^ t24;
  t31 = t22 ^ t26;
  t32 = t31 & t30;
  t33 = t32 ^ t24;
  t34 = t23 ^ t33;
  t35 = t27 ^ t33;
  t36 = t24 & t35;
  t37 = t36 ^ t34;
  t38 = t27 ^ t36;
  t39 = t29 & t38;
  t40 = t25 ^ t39;

  t41 = t40 ^ t37;
  t42 = t29 ^ t33;
  t43 = t29 ^ t40;
  t44 = t33 ^ t37;
  t45 = t42 ^ t41;
  z0 = t44 & y15;
  z1 = t37 & y6;
  z2 = t33 & x7;
  z3 = t43 & y16;
  z4 = t40 & y1;
  z5 = t29 & y7;
  z6 = t42 & y11;
  z7 = t45 & y17;
  z8 = t41 & y10;
  z9 = t44 & y12;
  z10 = t37 & y3;
  z11 = t33 & y4;
  z12 = t43 & y13;
  z13 = t40 & y5;
  z14 = t29 & y2;
  z15 = t42 & y9;
  z16 = t45 & y14;
  z17 = t41 & y8;

  /*
   * Bottom linear transformation.
   */
  t46 = z15 ^ z16;
  t47 = z10 ^ z11;
  t48 = z5 ^ z13;
  t49 = z9 ^ z10;
  t50 = z2 ^ z12;
  t51 = z2 ^ z5;
  t52 = z7 ^ z8;
  t53 = z0 ^ z3;
  t54 = z6 ^ z7;
  t55 = z16 ^ z17;
  t56 = z12 ^ t48;
  t57 = t50 ^ t53;
  t58 = z4 ^ t46;
  t59 = z3 ^ t54;
  t60 = t46 ^ t57;
  t61 = z14 ^ t57;
  t62 = t52 ^ t58;
  t63 = t49 ^ t58;
  t64 = z4 ^ t59;
  t65 = t61 ^ t62;
  t66 = z1 ^ t63;
  s0 = t59 ^ t63;
  s6 = t56 ^ ~t62;
  s7 = t48 ^ ~t60;
  t67 = t64 ^ t65;
  s3 = t53 ^ t66;
  s4 = t51 ^ t66;
  s5 = t47 ^ t65;
  s1 = t64 ^ ~s3;
  s2 = t55 ^ ~t67;

  q[7] = s0;
  q[6] = s1;
  q[5] = s2;
  q[4] = s3;
  q[3] = s4;
  q[2] = s5;
  q[1] = s6;
  q[0] = s7;
}


function br_aes_ct64_ortho(q) {
  const SWAPN = (cl, ch, s, x, y) => {
    const a = x;
    const b = y;
    x = (a & cl) | ((b & cl) << s);
    y = ((a & ch) >> s) | (b & ch);
    return [x, y];
  }

  const SWAP2 = (x, y) => SWAPN(0x5555555555555555, 0xAAAAAAAAAAAAAAAA, 1, x, y);
  const SWAP4 = (x, y) => SWAPN(0x3333333333333333, 0xCCCCCCCCCCCCCCCC, 2, x, y);
  const SWAP8 = (x, y) => SWAPN(0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0, 4, x, y);

  [q[0], q[1]] = SWAP2(q[0], q[1]);
  [q[2], q[3]] = SWAP2(q[2], q[3]);
  [q[4], q[5]] = SWAP2(q[4], q[5]);
  [q[6], q[7]] = SWAP2(q[6], q[7]);

  [q[0], q[2]] = SWAP4(q[0], q[2]);
  [q[1], q[3]] = SWAP4(q[1], q[3]);
  [q[4], q[6]] = SWAP4(q[4], q[6]);
  [q[5], q[7]] = SWAP4(q[5], q[7]);

  [q[0], q[4]] = SWAP8(q[0], q[4]);
  [q[1], q[5]] = SWAP8(q[1], q[5]);
  [q[2], q[6]] = SWAP8(q[2], q[6]);
  [q[3], q[7]] = SWAP8(q[3], q[7]);
}

const Rcon = [
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
];

function sub_word(x) {
  const q = new Array(8).fill(0);
  q[0] = x;
  br_aes_ct64_ortho(q);
  br_aes_ct64_bitslice_Sbox(q);
  br_aes_ct64_ortho(q);
  return q[0];
}

function br_aes_ct64_keysched(comp_skey, key) {
  const skey = new Array(60).fill(0);
  const key_len = 32;
  const nk = key_len >> 2;
  const nkf = (14 + 1) << 2;
  br_range_dec32le(skey, nk, key);
  let tmp = skey[nk - 1];
  let j = 0;
  let k = 0;
  for (let i = nk; i < nkf; i++) {
    if (j === 0) {
      tmp = (tmp << 24) | (tmp >> 8);
      tmp = sub_word(tmp) ^ Rcon[k];
    } else if (nk > 6 && j === 4) {
      tmp = sub_word(tmp);
    }
    tmp ^= skey[i - nk];
    skey[i] = tmp;
    if (++j === nk) {
      j = 0;
      k++;
    }
  }
  for (let i = 0, j = 0; i < nkf; i += 4, j += 2) {
    const q = new Array(8).fill(0);
    br_aes_ct64_interleave_in(q.slice(0, 4), q.slice(4), skey.slice(i, i + 4));
    q[1] = q[0];
    q[2] = q[0];
    q[3] = q[0];
    q[5] = q[4];
    q[6] = q[4];
    q[7] = q[4];
    br_aes_ct64_ortho(q);
    comp_skey[j] =
      (q[0] & 0x1111111111111111) |
      (q[1] & 0x2222222222222222) |
      (q[2] & 0x4444444444444444) |
      (q[3] & 0x8888888888888888);
    comp_skey[j + 1] =
      (q[4] & 0x1111111111111111) |
      (q[5] & 0x2222222222222222) |
      (q[6] & 0x4444444444444444) |
      (q[7] & 0x8888888888888888);
  }
}

function br_aes_ct64_skey_expand(skey, comp_skey) {
  const n = (14 + 1) << 1;
  for (let u = 0, v = 0; u < n; u++, v += 4) {
    let x0, x1, x2, x3;
    x0 = x1 = x2 = x3 = comp_skey[u];
    x0 &= 0x1111111111111111;
    x1 &= 0x2222222222222222;
    x2 &= 0x4444444444444444;
    x3 &= 0x8888888888888888;
    x1 >>= 1;
    x2 >>= 2;
    x3 >>= 3;
    skey[v] = (x0 << 4) - x0;
    skey[v + 1] = (x1 << 4) - x1;
    skey[v + 2] = (x2 << 4) - x2;
    skey[v + 3] = (x3 << 4) - x3;
  }
}

function add_round_key(q, sk) {
  q[0] ^= sk[0];
  q[1] ^= sk[1];
  q[2] ^= sk[2];
  q[3] ^= sk[3];
  q[4] ^= sk[4];
  q[5] ^= sk[5];
  q[6] ^= sk[6];
  q[7] ^= sk[7];
}

function shift_rows(q) {
  for (let i = 0; i < 8; i++) {
    const x = q[i];
    q[i] =
      (x & 0x000000000000FFFF) |
      ((x & 0x00000000FFF00000) >> 4) |
      ((x & 0x00000000000F0000) << 12) |
      ((x & 0x0000FF0000000000) >> 8) |
      ((x & 0x000000FF00000000) << 8) |
      ((x & 0xF000000000000000) >> 12) |
      ((x & 0x0FFF000000000000) << 4);
  }
}

function rotr32(x) {
  return (x << 32) | (x >> 32);
}

function mix_columns(q) {
  let q0, q1, q2, q3, q4, q5, q6, q7;
  let r0, r1, r2, r3, r4, r5, r6, r7;
  q0 = q[0];
  q1 = q[1];
  q2 = q[2];
  q3 = q[3];
  q4 = q[4];
  q5 = q[5];
  q6 = q[6];
  q7 = q[7];
  r0 = (q0 >> 16) | (q0 << 48);
  r1 = (q1 >> 16) | (q1 << 48);
  r2 = (q2 >> 16) | (q2 << 48);
  r3 = (q3 >> 16) | (q3 << 48);
  r4 = (q4 >> 16) | (q4 << 48);
  r5 = (q5 >> 16) | (q5 << 48);
  r6 = (q6 >> 16) | (q6 << 48);
  r7 = (q7 >> 16) | (q7 << 48);
  q[0] = q7 ^ r7 ^ r0 ^ rotr32(q0 ^ r0);
  q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotr32(q1 ^ r1);
  q[2] = q1 ^ r1 ^ r2 ^ rotr32(q2 ^ r2);
  q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotr32(q3 ^ r3);
  q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotr32(q4 ^ r4);
q[5] = q4 ^ r4 ^ r5 ^ rotr32(q5 ^ r5);
q[6] = q5 ^ r5 ^ r6 ^ rotr32(q6 ^ r6);
q[7] = q6 ^ r6 ^ r7 ^ rotr32(q7 ^ r7);
}

function inc4_be(x) {
  x[0] = ((x[0] >>> 24) & 0xff) | ((x[0] >>> 8) & 0xff00) | ((x[0] << 8) & 0xff0000) | ((x[0] << 24) & 0xff000000);
  x[0] += 4;
  x[0] = ((x[0] >>> 24) & 0xff) | ((x[0] >>> 8) & 0xff00) | ((x[0] << 8) & 0xff0000) | ((x[0] << 24) & 0xff000000);
}

function aes_ctr4x(out, ivw, sk_exp) {
  var w = new Uint32Array(16);
  var q = new BigInt64Array(8);
  var i;

  w.set(ivw);
  for (i = 0; i < 4; i++) {
    br_aes_ct64_interleave_in(q.subarray(i, i + 1), q.subarray(i + 4, i + 5), w.subarray(i << 2, (i << 2) + 4));
  }
  br_aes_ct64_ortho(q);

  add_round_key(q, sk_exp);
  for (i = 1; i < 14; i++) {
    br_aes_ct64_bitslice_Sbox(q);
    shift_rows(q);
    mix_columns(q);
    add_round_key(q, sk_exp.subarray(i << 3, (i << 3) + 8));
  }
  br_aes_ct64_bitslice_Sbox(q);
  shift_rows(q);
  add_round_key(q, sk_exp.subarray(112, 120));

  br_aes_ct64_ortho(q);
  for (i = 0; i < 4; i ++) {
    br_aes_ct64_interleave_out(w.subarray(i << 2, (i << 2) + 4), q.subarray(i, i + 1), q.subarray(i + 4, i + 5));
  }
  br_range_enc32le(out, w, 16);

  /* Increase counter for next 4 blocks */
  inc4_be(ivw.subarray(3, 4));
  inc4_be(ivw.subarray(7, 8));
  inc4_be(ivw.subarray(11, 12));
  inc4_be(ivw.subarray(15, 16));
}

function br_aes_ct64_ctr_init(sk_exp, key) {
  var skey = new Uint32Array(30);

  br_aes_ct64_keysched(skey, key);
  br_aes_ct64_skey_expand(sk_exp, skey);
}

function aes256ctr_init(s, key, nonce) {
  br_aes_ct64_ctr_init(s.sk_exp, key);

  br_range_dec32le(s.ivw, 3, nonce);
  s.ivw.set(s.ivw.subarray(0, 3), 4);
  s.ivw.set(s.ivw.subarray(0, 3), 8);
  s.ivw.set(s.ivw.subarray(0, 3), 12);
  s.ivw[3] = ((s.ivw[3] >>> 24) & 0xff) | ((s.ivw[3] >>> 8) & 0xff00) | ((s.ivw[3] << 8) & 0xff0000) | ((s.ivw[3] << 24) & 0xff000000);
  s.ivw[7] = ((s.ivw[7] >>> 24) & 0xff) | ((s.ivw[7] >>> 8) & 0xff00) | ((s.ivw[7] << 8) & 0xff0000) | ((s.ivw[7] << 24) & 0xff000000);
  s.ivw[11] = ((s.ivw[11] >>> 24) & 0xff) | ((s.ivw[11] >>> 8) & 0xff00) | ((s.ivw[11] << 8) & 0xff0000) | ((s.ivw[11] << 24) & 0xff000000);
  s.ivw[15] = ((s.ivw[15] >>> 24) & 0xff) | ((s.ivw[15] >>> 8) & 0xff00) | ((s.ivw[15] << 8) & 0xff0000) | ((s.ivw[15] << 24) & 0xff000000);
}

function aes256ctr_squeezeblocks(out, nblocks, s) {
  while (nblocks > 0) {
    aes_ctr4x(out, s.ivw, s.sk_exp);
    out = out.subarray(64);
    nblocks--;
  }
}