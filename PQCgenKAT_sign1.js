// Import necessary modules
const fs = require('fs');
const { randombytes_init, randombytes, crypto_sign_keypair, crypto_sign, crypto_sign_open } = require('crypto');

// Define constants
const MAX_MARKER_LEN = 50;
const KAT_SUCCESS = 0;
const KAT_FILE_OPEN_ERROR = -1;
const KAT_DATA_ERROR = -3;
const KAT_CRYPTO_FAILURE = -4;

// Define helper functions
function FindMarker(infile, marker) {
  let line;
  while ((line = infile.readLine()) !== null) {
    if (line.includes(marker)) {
      return true;
    }
  }
  return false;
}

function ReadHex(infile, a, Length, str) {
  const line = infile.readLine();
  if (!line.includes(str)) {
    return false;
  }
  const hex = line.slice(str.length);
  if (hex.length !== Length * 2) {
    return false;
  }
  for (let i = 0; i < Length; i++) {
    a[i] = parseInt(hex.slice(i * 2, (i + 1) * 2), 16);
  }
  return true;
}

function fprintBstr(fp, s, a, l) {
  fp.write(`${s}`);
  for (let i = 0; i < l; i++) {
    fp.write(`${a[i].toString(16).padStart(2, '0')}`);
  }
  fp.write('\n');
}

// Define main function
function main() {
  const fn_req = `PQCsignKAT_${CRYPTO_ALGNAME}.req`;
  const fn_rsp = `PQCsignKAT_${CRYPTO_ALGNAME}.rsp`;
  let fp_req, fp_rsp;
  const seed = new Uint8Array(48);
  const msg = new Uint8Array(3300);
  const entropy_input = new Uint8Array(48);
  let m, sm, m1;
  let mlen, smlen, mlen1;
  let count;
  let done;
  const pk = new Uint8Array(crypto_sign_keypair.publicKeyLength);
  const sk = new Uint8Array(crypto_sign_keypair.secretKeyLength);
  let ret_val;

  // Create the REQUEST file
  fp_req = fs.createWriteStream(fn_req);
  if (!fp_req) {
    console.log(`Couldn't open <${fn_req}> for write`);
    return KAT_FILE_OPEN_ERROR;
  }
  fp_rsp = fs.createWriteStream(fn_rsp);
  if (!fp_rsp) {
    console.log(`Couldn't open <${fn_rsp}> for write`);
    return KAT_FILE_OPEN_ERROR;
  }

  for (let i = 0; i < 48; i++) {
    entropy_input[i] = i;
  }

  randombytes_init(entropy_input, null, 256);
  for (let i = 0; i < 100; i++) {
    fp_req.write(`count = ${i}\n`);
    randombytes(seed);
    fprintBstr(fp_req, 'seed = ', seed, 48);
    mlen = 33 * (i + 1);
    fp_req.write(`mlen = ${mlen}\n`);
    randombytes(msg, mlen);
    fprintBstr(fp_req, 'msg = ', msg, mlen);
    fp_req.write('pk =\n');
    fp_req.write('sk =\n');
    fp_req.write('smlen =\n');
    fp_req.write('sm =\n');
  }
  fp_req.close();

  //Create the RESPONSE file based on what's in the REQUEST file
  fp_req = fs.createReadStream(fn_req);
  if (!fp_req) {
    console.log(`Couldn't open <${fn_req}> for read`);
    return KAT_FILE_OPEN_ERROR;
  }

  fp_rsp.write(`# ${CRYPTO_ALGNAME}\n`);
  done = false;
  do {
    if (FindMarker(fp_req, 'count = ')) {
      count = parseInt(fp_req.readLine().slice(8));
    } else {
      done = true;
      break;
    }
    fp_rsp.write(`count = ${count}\n`);

    if (!ReadHex(fp_req, seed, 48, 'seed = ')) {
      console.log(`ERROR: unable to read 'seed' from <${fn_req}>`);
      return KAT_DATA_ERROR;
    }
    fprintBstr(fp_rsp, 'seed = ', seed, 48);

    randombytes_init(seed, null, 256);

    if (FindMarker(fp_req, 'mlen = ')) {
      mlen = parseInt(fp_req.readLine().slice(7));
    } else {
      console.log(`ERROR: unable to read 'mlen' from <${fn_req}>`);
      return KAT_DATA_ERROR;
    }
    fp_rsp.write(`mlen = ${mlen}\n`);

    m = new Uint8Array(mlen);
    m1 = new Uint8Array(mlen + crypto_sign_BYTES);
    sm = new Uint8Array(mlen + crypto_sign_BYTES);

    if (!ReadHex(fp_req, m, mlen, 'msg = ')) {
      console.log(`ERROR: unable to read 'msg' from <${fn_req}>`);
      return KAT_DATA_ERROR;
    }
    fprintBstr(fp_rsp, 'msg = ', m, mlen);

    // Generate the public/private keypair
    crypto_sign_keypair(pk, sk);
    fprintBstr(fp_rsp, 'pk = ', pk, crypto_sign_PUBLICKEYBYTES);
    fprintBstr(fp_rsp, 'sk = ', sk, crypto_sign_SECRETKEYBYTES);

    crypto_sign(sm, m, sk);
    smlen = crypto_sign_BYTES + mlen;
    fp_rsp.write(`smlen = ${smlen}\n`);
    fprintBstr(fp_rsp, 'sm = ', sm, smlen);
    fp_rsp.write('\n');

    crypto_sign_open(m1, sm, pk);
    mlen1 = mlen;

    if (mlen !== mlen1) {
      console.log(`crypto_sign_open returned bad 'mlen': Got <${mlen1}>, expected <${mlen}>`);
      return KAT_CRYPTO_FAILURE;
    }

    if (!m.every((val, i) => val === m1[i])) {
      console.log(`crypto_sign_open returned bad 'm' value`);
      return KAT_CRYPTO_FAILURE;
    }

    m = null;
    m1 = null;
    sm = null;
  } while (!done);

  fp_req.close();
  fp_rsp.close();

  return KAT_SUCCESS;
}