const NROUNDS = 24;

function ROL(a, offset) {
  return ((a << offset) ^ (a >> (64-offset)));
}

function load64(x) {
  let r = 0;

  for(let i=0;i<8;i++)
    r |= (x[i] << (8*i));

  return r;
}

function store64(x, u) {
  for(let i=0;i<8;i++)
    x[i] = (u >> (8*i)) & 0xff;
}

/* Keccak round constants */
const KeccakF_RoundConstants = [
  0x0000000000000001n,
  0x0000000000008082n,
  0x800000000000808an,
  0x8000000080008000n,
  0x000000000000808bn,
  0x0000000080000001n,
  0x8000000080008081n,
  0x8000000000008009n,
  0x000000000000008an,
  0x0000000000000088n,
  0x0000000080008009n,
  0x000000008000000an,
  0x000000008000808bn,
  0x800000000000008bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x000000000000800an,
  0x800000008000000an,
  0x8000000080008081n,
  0x8000000000008080n,
  0x0000000080000001n,
  0x8000000080008008n
];

function KeccakF1600_StatePermute(state) {
  let round;

  let Aba, Abe, Abi, Abo, Abu;
  let Aga, Age, Agi, Ago, Agu;
  let Aka, Ake, Aki, Ako, Aku;
  let Ama, Ame, Ami, Amo, Amu;
  let Asa, Ase, Asi, Aso, Asu;
  let BCa, BCe, BCi, BCo, BCu;
  let Da, De, Di, Do, Du;
  let Eba, Ebe, Ebi, Ebo, Ebu;
  let Ega, Ege, Egi, Ego, Egu;
  let Eka, Eke, Eki, Eko, Eku;
  let Ema, Eme, Emi, Emo, Emu;
  let Esa, Ese, Esi, Eso, Esu;

  Aba = state[0];
  Abe = state[1];
  Abi = state[2];
  Abo = state[3];
  Abu = state[4];
  Aga = state[5];
  Age = state[6];
  Agi = state[7];
  Ago = state[8];
  Agu = state[9];
  Aka = state[10];
  Ake = state[11];
  Aki = state[12];
  Ako = state[13];
  Aku = state[14];
  Ama = state[15];
  Ame = state[16];
  Ami = state[17];
  Amo = state[18];
  Amu = state[19];
  Asa = state[20];
  Ase = state[21];
  Asi = state[22];
  Aso = state[23];
  Asu = state[24];

  for (round = 0; round < NROUNDS; round += 2) {
    // code for each round

    BCa = Aba^Aga^Aka^Ama^Asa;
    BCe = Abe^Age^Ake^Ame^Ase;
    BCi = Abi^Agi^Aki^Ami^Asi;
    BCo = Abo^Ago^Ako^Amo^Aso;
    BCu = Abu^Agu^Aku^Amu^Asu;

    Da = BCu^ROL(BCe, 1);
    De = BCa^ROL(BCi, 1);
    Di = BCe^ROL(BCo, 1);
    Do = BCi^ROL(BCu, 1);
    Du = BCo^ROL(BCa, 1);

    Aba ^= Da;
    BCa = Aba;
    Age ^= De;
    BCe = ROL(Age, 44);
    Aki ^= Di;
    BCi = ROL(Aki, 43);
    Amo ^= Do;
    BCo = ROL(Amo, 21);
    Asu ^= Du;
    BCu = ROL(Asu, 14);
    let Eba = BCa ^((~BCe)&  BCi );
    Eba ^= KeccakF_RoundConstants[round];
    let Ebe = BCe ^((~BCi)&  BCo );
    let Ebi = BCi ^((~BCo)&  BCu );
    let Ebo = BCo ^((~BCu)&  BCa );
    let Ebu = BCu ^((~BCa)&  BCe );

    Abo ^= Do;
    BCa = ROL(Abo, 28);
    Agu ^= Du;
    BCe = ROL(Agu, 20);
    Aka ^= Da;
    BCi = ROL(Aka,  3);
    Ame ^= De;
    BCo = ROL(Ame, 45);
    Asi ^= Di;
    BCu = ROL(Asi, 61);
    let Ega = BCa ^((~BCe)&  BCi );
    let Ege = BCe ^((~BCi)&  BCo );
    let Egi = BCi ^((~BCo)&  BCu );
    let Ego = BCo ^((~BCu)&  BCa );
    let Egu = BCu ^((~BCa)&  BCe );

    Abe ^= De;
    BCa = ROL(Abe,  1);
    Agi ^= Di;
    BCe = ROL(Agi,  6);
    Ako ^= Do;
    BCi = ROL(Ako, 25);
    Amu ^= Du;
    BCo = ROL(Amu,  8);
    Asa ^= Da;
    BCu = ROL(Asa, 18);
    let Eka = BCa ^((~BCe)&  BCi );
    let Eke = BCe ^((~BCi)&  BCo );
    let Eki = BCi ^((~BCo)&  BCu );
    let Eko = BCo ^((~BCu)&  BCa );
    let Eku = BCu ^((~BCa)&  BCe );

    Abu ^= Du;
    BCa = ROL(Abu, 27);
    Aga ^= Da;
    BCe = ROL(Aga, 36);
    Ake ^= De;
    BCi = ROL(Ake, 10);
    Ami ^= Di;
    BCo = ROL(Ami, 15);
    Aso ^= Do;
    BCu = ROL(Aso, 56);
    let Ema = BCa ^((~BCe)&  BCi );
    let Eme = BCe ^((~BCi)&  BCo );
    let Emi = BCi ^((~BCo)&  BCu );
    let Emo = BCo ^((~BCu)&  BCa );
    let Emu = BCu ^((~BCa)&  BCe );

    Abi ^= Di;
    BCa = ROL(Abi, 62);
    Ago ^= Do;
    BCe = ROL(Ago, 55);
    Aku ^= Du;
    BCi = ROL(Aku, 39);
    Ama ^= Da;
    BCo = ROL(Ama, 41);
    Ase ^= De;
    BCu = ROL(Ase,  2);
    let Esa = BCa ^((~BCe)&  BCi );
    let Ese = BCe ^((~BCi)&  BCo );
    let Esi = BCi ^((~BCo)&  BCu );
    let Eso = BCo ^((~BCu)&  BCa );
    let Esu = BCu ^((~BCa)&  BCe );

    BCa = Eba^Ega^Eka^Ema^Esa;
    BCe = Ebe^Ege^Eke^Eme^Ese;
    BCi = Ebi^Egi^Eki^Emi^Esi;
    BCo = Ebo^Ego^Eko^Emo^Eso;
    BCu = Ebu^Egu^Eku^Emu^Esu;

    Da = BCu^ROL(BCe, 1);
    De = BCa^ROL(BCi, 1);
    Di = BCe^ROL(BCo, 1);
    Do = BCi^ROL(BCu, 1);
    Du = BCo^ROL(BCa, 1);

    Eba ^= Da;
    BCa = Eba;
    Ege ^= De;
    BCe = ROL(Ege, 44);
    Eki ^= Di;
    BCi = ROL(Eki, 43);
    Emo ^= Do;
    BCo = ROL(Emo, 21);
    Esu ^= Du;
    BCu = ROL(Esu, 14);
    Aba = BCa ^((~BCe)&  BCi );
    Aba ^= KeccakF_RoundConstants[round+1];
    Abe = BCe ^((~BCi)&  BCo );
    Abi = BCi ^((~BCo)&  BCu );
    Abo = BCo ^((~BCu)&  BCa );
    Abu = BCu ^((~BCa)&  BCe );

    Ebo ^= Do;
    BCa = ROL(Ebo, 28);
    Egu ^= Du;
    BCe = ROL(Egu, 20);
    Eka ^= Da;
    BCi = ROL(Eka, 3);
    Eme ^= De;
    BCo = ROL(Eme, 45);
    Esi ^= Di;
    BCu = ROL(Esi, 61);
    Aga = BCa ^((~BCe)&  BCi );
    Age = BCe ^((~BCi)&  BCo );
    Agi = BCi ^((~BCo)&  BCu );
    Ago = BCo ^((~BCu)&  BCa );
    Agu = BCu ^((~BCa)&  BCe );

    Ebe ^= De;
    BCa = ROL(Ebe, 1);
    Egi ^= Di;
    BCe = ROL(Egi, 6);
    Eko ^= Do;
    BCi = ROL(Eko, 25);
    Emu ^= Du;
    BCo = ROL(Emu, 8);
    Esa ^= Da;
    BCu = ROL(Esa, 18);
    Aka = BCa ^((~BCe)&  BCi );
    Ake = BCe ^((~BCi)&  BCo );
    Aki = BCi ^((~BCo)&  BCu );
    Ako = BCo ^((~BCu)&  BCa );
    Aku = BCu ^((~BCa)&  BCe );

    Ebu ^= Du;
    BCa = ROL(Ebu, 27);
    Ega ^= Da;
    BCe = ROL(Ega, 36);
    Eke ^= De;
    BCi = ROL(Eke, 10);
    Emi ^= Di;
    BCo = ROL(Emi, 15);
    Eso ^= Do;
    BCu = ROL(Eso, 56);
    Ama = BCa ^((~BCe)&  BCi );
    Ame = BCe ^((~BCi)&  BCo );
    Ami = BCi ^((~BCo)&  BCu );
    Amo = BCo ^((~BCu)&  BCa );
    Amu = BCu ^((~BCa)&  BCe );

    Ebi ^= Di;
    BCa = ROL(Ebi, 62);
    Ego ^= Do;
    BCe = ROL(Ego, 55);
    Eku ^= Du;
    BCi = ROL(Eku, 39);
    Ema ^= Da;
    BCo = ROL(Ema, 41);
    Ese ^= De;
    BCu = ROL(Ese, 2);
    Asa = BCa ^((~BCe)&  BCi );
    Ase = BCe ^((~BCi)&  BCo );
    Asi =   BCi ^((~BCo)&  BCu );
    Aso =   BCo ^((~BCu)&  BCa );
    Asu =   BCu ^((~BCa)&  BCe );
  }

  // copyToState(state, A)
  state[0] = Aba;
  state[1] = Abe;
  state[2] = Abi;
  state[3] = Abo;
  state[4] = Abu;
  state[5] = Aga;
  state[6] = Age;
  state[7] = Agi;
  state[8] = Ago;
  state[9] = Agu;
  state[10] = Aka;
  state[11] = Ake;
  state[12] = Aki;
  state[13] = Ako;
  state[14] = Aku;
  state[15] = Ama;
  state[16] = Ame;
  state[17] = Ami;
  state[18] = Amo;
  state[19] = Amu;
  state[20] = Asa;
  state[21] = Ase;
  state[22] = Asi;
  state[23] = Aso;
  state[24] = Asu;
}

function keccak_init(s) {
  for (let i = 0; i < 25; i++) {
    s[i] = 0;
  }
}

function keccak_absorb(s, pos, r, inData, inlen) {
  let i;

  while (pos + inlen >= r) {
    for (i = pos; i < r; i++) {
      s[Math.floor(i / 8)] ^= inData.shift() << 8 * (i % 8);
    }
    inlen -= r - pos;
    KeccakF1600_StatePermute(s);
    pos = 0;
  }

  for (i = pos; i < pos + inlen; i++) {
    s[Math.floor(i / 8)] ^= inData.shift() << 8 * (i % 8);
  }

  return i;
}

function keccak_finalize(s, pos, r, p) {
  s[Math.floor(pos / 8)] ^= p << 8 * (pos % 8);
  s[Math.floor(r / 8) - 1] ^= 1n << 63n;
}

function keccak_squeeze(out, outlen, s, pos, r) {
  let i;

  while (outlen) {
    if (pos === r) {
      KeccakF1600_StatePermute(s);
      pos = 0;
    }
    for (i = pos; i < r && i < pos + outlen; i++) {
      out.push(Number(s[Math.floor(i / 8)] >> 8 * (i % 8)) & 0xff);
    }
    outlen -= i - pos;
    pos = i;
  }

  return pos;
}

function keccak_absorb_once(s, r, inData, inlen, p) {
  let i;

  for (i = 0; i < 25; i++) {
    s[i] = 0n;
  }

  while (inlen >= r) {
    for (i = 0; i < r / 8; i++) {
      s[i] ^= load64(inData.slice(8 * i, 8 * i + 8));
    }
    inData = inData.slice(r);
    inlen -= r;
    KeccakF1600_StatePermute(s);
  }

  for (i = 0; i < inlen; i++) {
    s[Math.floor(i / 8)] ^= BigInt(inData[i]) << 8 * (i % 8);
  }

  s[Math.floor(i / 8)] ^= BigInt(p) << 8 * (i % 8);
  s[Math.floor((r - 1) / 8)] ^= 1n << 63n;
}

function keccak_squeezeblocks(out, nblocks, s, r) {
  let i;

  while (nblocks) {
    KeccakF1600_StatePermute(s);
    for (i = 0; i < r / 8; i++) {
      store64(out.slice(8 * i, 8 * i + 8), s[i]);
    }
    out = out.slice(r);
    nblocks -= 1;
  }
}

function shake128_init(state) {
  keccak_init(state.s);
  state.pos = 0;
}

function shake128_absorb(state, inn, inlen) {
  state.pos = keccak_absorb(state.s, state.pos, SHAKE128_RATE, inn, inlen);
}

function shake128_finalize(state) {
  keccak_finalize(state.s, state.pos, SHAKE128_RATE, 0x1F);
  state.pos = SHAKE128_RATE;
}

function shake128_squeeze(out, outlen, state) {
  state.pos = keccak_squeeze(out, outlen, state.s, state.pos, SHAKE128_RATE);
}

function shake128_absorb_once(state, inn, inlen) {
  keccak_absorb_once(state.s, SHAKE128_RATE, inn, inlen, 0x1F);
  state.pos = SHAKE128_RATE;
}

function shake128_squeezeblocks(out, nblocks, state) {
  keccak_squeezeblocks(out, nblocks, state.s, SHAKE128_RATE);
}

function shake256_init(state) {
  keccak_init(state.s);
  state.pos = 0;
}

function shake256_absorb(state, inn, inlen) {
  state.pos = keccak_absorb(state.s, state.pos, SHAKE256_RATE, inn, inlen);
}

function shake256_finalize(state) {
  keccak_finalize(state.s, state.pos, SHAKE256_RATE, 0x1F);
  state.pos = SHAKE256_RATE;
}

function shake256_squeeze(out, outlen, state) {
  state.pos = keccak_squeeze(out, outlen, state.s, state.pos, SHAKE256_RATE);
}

function shake256_absorb_once(state, inn, inlen) {
  keccak_absorb_once(state.s, SHAKE256_RATE, inn, inlen, 0x1F);
  state.pos = SHAKE256_RATE;
}

function shake256_squeezeblocks(out, nblocks, state) {
  keccak_squeezeblocks(out, nblocks, state.s, SHAKE256_RATE);
}

function shake128(out, outlen, inn, inlen) {
  let nblocks;
  let state = {s: [], pos: 0};

  shake128_absorb_once(state, inn, inlen);
  nblocks = outlen/SHAKE128_RATE;
  shake128_squeezeblocks(out, nblocks, state);
  outlen -= nblocks*SHAKE128_RATE;
  out += nblocks*SHAKE128_RATE;
  shake128_squeeze(out, outlen, state);
}

function shake256(out, outlen, inn, inlen) {
  let nblocks;
  let state = {s: [], pos: 0};

  shake256_absorb_once(state, inn, inlen);
  nblocks = outlen/SHAKE256_RATE;
  shake256_squeezeblocks(out, nblocks, state);
  outlen -= nblocks*SHAKE256_RATE;
  out += nblocks*SHAKE256_RATE;
  shake256_squeeze(out, outlen, state);
}

function sha3_256(h, inData, inlen) {
  let i;
  let s = new Array(25).fill(0);

  keccak_absorb_once(s, SHA3_256_RATE, inData, inlen, 0x06);
  KeccakF1600_StatePermute(s);
  for(i=0;i<4;i++)
    store64(h+8*i,s[i]);
}

function sha3_512(h, inData, inlen) {
  let i;
  let s = new Array(25).fill(0);

  keccak_absorb_once(s, SHA3_512_RATE, inData, inlen, 0x06);
  KeccakF1600_StatePermute(s);
  for(i=0;i<8;i++)
    store64(h+8*i,s[i]);
}