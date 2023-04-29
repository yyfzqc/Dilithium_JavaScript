
// #ifdef _WIN32

function randombytes(out, outlen) {
  let ctx;
  let len;

  if(!CryptAcquireContext(ctx, null, null, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    throw new Error("CryptAcquireContext failed");

  while(outlen > 0) {
    len = (outlen > 1048576) ? 1048576 : outlen;
    if(!CryptGenRandom(ctx, len, out))
      throw new Error("CryptGenRandom failed");

    out += len;
    outlen -= len;
  }

  if(!CryptReleaseContext(ctx, 0))
    throw new Error("CryptReleaseContext failed");
}
// #elif defined(__linux__) && defined(SYS_getrandom)
function randombytes(out, outlen) {
  let ret;

  while(outlen > 0) {
    ret = syscall(SYS_getrandom, out, outlen, 0);
    if(ret == -1 && errno == EINTR)
      continue;
    else if(ret == -1)
      abort();

    out += ret;
    outlen -= ret;
  }
}

// #else
function randombytes(out, outlen) {
  let fd = -1;
  let ret;

  while(fd === -1) {
    fd = fs.openSync("/dev/urandom", "r");
    if(fd === -1 && errno === "EINTR")
      continue;
    else if(fd === -1)
      throw new Error("Failed to open /dev/urandom");
  }

  while(outlen > 0) {
    ret = fs.readSync(fd, out, outlen);
    if(ret === -1 && errno === "EINTR")
      continue;
    else if(ret === -1)
      throw new Error("Failed to read from /dev/urandom");

    out = out.slice(ret);
    outlen -= ret;
  }


// #endif