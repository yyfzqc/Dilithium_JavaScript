const crypto = require('crypto');

function seedexpander_init(ctx, seed, diversifier, maxlen) {
    if (maxlen >= 0x100000000) {
        return RNG_BAD_MAXLEN;
    }

    ctx.length_remaining = maxlen;

    memcpy(ctx.key, seed, 32);

    memcpy(ctx.ctr, diversifier, 8);
    ctx.ctr[11] = maxlen % 256;
    maxlen >>= 8;
    ctx.ctr[10] = maxlen % 256;
    maxlen >>= 8;
    ctx.ctr[9] = maxlen % 256;
    maxlen >>= 8;
    ctx.ctr[8] = maxlen % 256;
    memset(ctx.ctr + 12, 0x00, 4);

    ctx.buffer_pos = 16;
    memset(ctx.buffer, 0x00, 16);

    return RNG_SUCCESS;
}

function seedexpander(ctx, x, xlen) {
    let offset;
    
    if (x == null)
        return RNG_BAD_OUTBUF;
    if (xlen >= ctx.length_remaining)
        return RNG_BAD_REQ_LEN;
    
    ctx.length_remaining -= xlen;
    
    offset = 0;
    while (xlen > 0) {
        if (xlen <= (16 - ctx.buffer_pos)) { // buffer has what we need
            x.copy(ctx.buffer, ctx.buffer_pos, offset, offset + xlen);
            ctx.buffer_pos += xlen;
            
            return RNG_SUCCESS;
        }
        
        // take what's in the buffer
        x.copy(ctx.buffer, ctx.buffer_pos, offset, offset + (16 - ctx.buffer_pos));
        xlen -= 16 - ctx.buffer_pos;
        offset += 16 - ctx.buffer_pos;
        
        AES256_ECB(ctx.key, ctx.ctr, ctx.buffer);
        ctx.buffer_pos = 0;
        
        //increment the counter
        for (let i = 15; i >= 12; i--) {
            if (ctx.ctr[i] === 0xff)
                ctx.ctr[i] = 0x00;
            else {
                ctx.ctr[i]++;
                break;
            }
        }
    }
    
    return RNG_SUCCESS;
}

function handleErrors() {
    console.error("OpenSSL error:");
    console.error(crypto.createHash("md5").update(openssl.getError()).digest("hex"));
    process.abort();
}


function AES256_ECB(key, ctr, buffer) {

    let ctx = crypto.createCipheriv("aes-256-ecb", key, Buffer.alloc(0));
    ctx.setAutoPadding(false);
    let cipherText = ctx.update(ctr);
    let finalText = ctx.final();
    let len = cipherText.length + finalText.length;
    Buffer.concat([cipherText, finalText], len).copy(buffer);
    let ciphertext_len = len;

    EVP_CIPHER_CTX_cleanup(ctx);
}

function randombytes_init(entropy_input, personalization_string, security_strength) {
    const seed_material = Buffer.alloc(48);
    entropy_input.copy(seed_material, 0, 0, 48);
    if (personalization_string) {
        for (let i = 0; i < 48; i++) {
            seed_material[i] ^= personalization_string[i];
        }
    }
    DRBG_ctx.Key.fill(0x00);
    DRBG_ctx.V.fill(0x00);
    AES256_CTR_DRBG_Update(seed_material, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter = 1;
}

function randombytes(x, xlen) {
    let block = new Uint8Array(16);
    let i = 0;

    while (xlen > 0) {
        for (var j = 15; j >= 0; j--) {
            if (DRBG_ctx.V[j] == 0xff) {
                DRBG_ctx.V[j] = 0x00;
            } else {
            DRBG_ctx.V[j]++;
            break;
          }
        }

        AES256_ECB(DRBG_ctx.Key, DRBG_ctx.V, block);

        if (xlen > 15) {
          x.set(block, i);
          i += 16;
          xlen -= 16;
        } else {
          x.set(block.subarray(0, xlen), i);
          xlen = 0;
        }
    }

    AES256_CTR_DRBG_Update(null, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter ++;

    return RNG_SUCCESS;
}


function AES256_CTR_DRBG_Update(provided_data, Key, V) {
  let temp = new Uint8Array(48);
  
  for (let i = 0; i < 3; i++) {
    // increment V
    for (let j = 15; j >= 0; j--) {
      if (V[j] == 0xff)
        V[j] = 0x00;
      else {
        V[j]++;
        break;
      }
    }
    
    AES256_ECB(Key, V, temp.subarray(i * 16, (i + 1) * 16));
  }
  
  if (provided_data != null) {
    for (let i = 0; i < 48; i++)
      temp[i] ^= provided_data[i];
  }
  
  Key.set(temp.subarray(0, 32));
  V.set(temp.subarray(32, 48));
}
