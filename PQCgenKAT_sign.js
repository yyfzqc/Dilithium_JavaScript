const utils = require('./rng');
// const utils = require('./sign');

const MAX_MARKER_LEN = 50;
const KAT_SUCCESS = 0;
const KAT_FILE_OPEN_ERROR = -1;
const KAT_DATA_ERROR = -3;
const KAT_CRYPTO_FAILURE = -4;

function FindMarker(infile, marker) {
    let line = new Array(MAX_MARKER_LEN);
    let i, len, curr_line;

    len = marker.length;
    if (len > MAX_MARKER_LEN - 1) len = MAX_MARKER_LEN - 1;

    for (i = 0; i < len; i++) {
    curr_line = infile.readChar();
    line[i] = curr_line;
    if (curr_line == -1) return false;
    }
    line[len] = '\0';

    while (true) {
        if (line.join('').startsWith(marker)) return true;

        for (i = 0; i < len - 1; i++) line[i] = line[i + 1];
            curr_line = infile.readChar();
        line[len - 1] = curr_line;
        if (curr_line == -1) return false;
        line[len] = '\0';
    }

  // shouldn't get here
    return false;
}


function readHex(infile, a, Length, str) {
    let i, ch, started;
    let ich;
    if (Length == 0) {
        a[0] = 0x00;
        return 1;
    }
    a.fill(0x00);
    started = 0;
    if (findMarker(infile, str)) {
        while ((ch = infile.read()) !== -1) {
            if (!isHexDigit(ch)) {
                if (!started) {
                    if (ch == '\n') break;
                    else continue;
                } else break;
            }
            started = 1;
            if (ch >= 48 && ch <= 57) ich = ch - 48;
            else if (ch >= 65 && ch <= 70) ich = ch - 65 + 10;
            else if (ch >= 97 && ch <= 102) ich = ch - 97 + 10;
            else ich = 0;
            for (i = 0; i < Length - 1; i++) a[i] = (a[i] << 4) | (a[i + 1] >> 4);
                a[Length - 1] = (a[Length - 1] << 4) | ich;
        }
    } else return 0;
    return 1;
}

function fprintBstr(fp, s, a, l) {
    let i;
    fprintf(fp, "%s", s);
    for (i = 0; i < l; i++) {
        fprintf(fp, "%02X", a[i]);
    }
    if (l == 0) {
        fprintf(fp, "00");
    }
    fprintf(fp, "\n");
}

function main() {
    let fn_req = "", fn_rsp = "";
    let fp_req = null, fp_rsp = null;
    let seed = new Uint8Array(48);
    let msg = new Uint8Array(3300);
    let entropy_input = new Uint8Array(48);
    let m, sm, m1;
    let mlen, smlen, mlen1;
    let count;
    let done;
    let pk = new Uint8Array(CRYPTO_PUBLICKEYBYTES);
    let sk = new Uint8Array(CRYPTO_SECRETKEYBYTES);
    let ret_val;

  // Create the REQUEST file
    fn_req = "PQCsignKAT_" + CRYPTO_ALGNAME.substring(0, 16) + ".req";
    fp_req = fs.openSync(fn_req, "w");
    fn_rsp = "PQCsignKAT_" + CRYPTO_ALGNAME.substring(0, 16) + ".rsp";
    fp_rsp = fs.openSync(fn_rsp, "w");

    for (let i = 0; i < 48; i++)
        entropy_input[i] = i;

    randombytes_init(entropy_input, null, 256);
    for (let i = 0; i < 100; i++) {
        fs.writeSync(fp_req, "count = " + i + "\n");
        randombytes(seed, 48);
        fprintBstr(fp_req, "seed = ", seed, 48);
        mlen = 33 * (i + 1);
        fs.writeSync(fp_req, "mlen = " + mlen + "\n");
        randombytes(msg, mlen);
        fprintBstr(fp_req, "msg = ", msg, mlen);
        fs.writeSync(fp_req, "pk =\n");
        fs.writeSync(fp_req, "sk =\n");
        fs.writeSync(fp_req, "smlen =\n");
        fs.writeSync(fp_req, "sm =\n\n");
    }
    fs.closeSync(fp_req);

  //Create the RESPONSE file based on what's in the REQUEST file
    fp_req = fs.openSync(fn_req, "r");
    fs.writeSync(fp_rsp, "# " + CRYPTO_ALGNAME + "\n\n");
    done = 0;
    do {
        if (FindMarker(fp_req, "count = ")) {
            count = parseInt(readline(fp_req));
        } else {
            done = 1;
            break;
        }
        fs.writeSync(fp_rsp, "count = " + count + "\n");

        if (!ReadHex(fp_req, seed, 48, "seed = ")) {
            console.log("ERROR: unable to read 'seed' from <" + fn_req + ">");
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "seed = ", seed, 48);

        randombytes_init(seed, null, 256);

        if (FindMarker(fp_req, "mlen = ")) {
            mlen = parseInt(readline(fp_req));
        } else {
            console.log("ERROR: unable to read 'mlen' from <" + fn_req + ">");
            return KAT_DATA_ERROR;
        }
        fs.writeSync(fp_rsp, "mlen = " + mlen + "\n");
        m = new Uint8Array(mlen);
        m1 = new Uint8Array(mlen + CRYPTO_BYTES);
        sm = new Uint8Array(mlen + CRYPTO_BYTES);

        if (!ReadHex(fp_req, m, mlen, "msg = ")) {
            console.log("ERROR: unable to read 'msg' from <%s>", fn_req);
            return KAT_DATA_ERROR;
        }

        fprintBstr(fp_rsp, "msg = ", m, mlen);

        // Generate the public/private keypair
        let kp = crypto_sign_keyPair();
        let pk = kp.publicKey;
        let sk = kp.secretKey;

        fprintBstr(fp_rsp, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);
        fprintBstr(fp_rsp, "sk = ", sk, CRYPTO_SECRETKEYBYTES);

        let signedMsg = crypto_sign(m, sk);

        fprintBstr(fp_rsp, "sm = ", signedMsg, signedMsg.length);
        fprintf(fp_rsp, "smlen = %lu\n", signedMsg.length);

        if (crypto_sign_open(m1, 0, signedMsg, signedMsg.length, pk) !== 0) {
            console.log("crypto_sign_open returned <%d>", ret_val);
            return KAT_CRYPTO_FAILURE;
        }

        if (mlen !== m1.subarray(0, mlen).length) {
            console.log("crypto_sign_open returned bad 'mlen': Got <%d>, expected <%d>", m1.subarray(0, mlen).length, mlen);
            return KAT_CRYPTO_FAILURE;
        }

        if (!m.subarray(0, mlen).every((v, i) => v === m1[i])) {
            console.log("crypto_sign_open returned bad 'm' value");
            return KAT_CRYPTO_FAILURE;
        }

        free(m);
        free(m1);
        free(sm);
    }while(!done);

    fs.closeSync(fp_req);
    fs.closeSync(fp_rsp);

    return KAT_SUCCESS;
}