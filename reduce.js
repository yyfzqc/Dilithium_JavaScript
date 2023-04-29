function montgomery_reduce(a) {
  let t;
  t = BigInt.asIntN(32, BigInt.asIntN(64, a) * BigInt(QINV));
  t = BigInt.asIntN(32, BigInt.asIntN(64, a) - BigInt.asIntN(64, t) * BigInt(Q)) >> 32n;
  return Number(t);
}

function reduce32(a) {
  let t;
  t = (a + (1 << 22)) >> 23;
  t = a - t * Q;
  return t;
}

function caddq(a) {
  a += (a >> 31) & Q;
  return a;
}

function freeze(a) {
  a = reduce32(a);
  a = caddq(a);
  return a;
}