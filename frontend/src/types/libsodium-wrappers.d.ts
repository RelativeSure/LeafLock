declare module 'libsodium-wrappers' {
  interface Sodium {
    ready: Promise<void>;
    crypto_secretbox_easy: (message: string | Uint8Array, nonce: Uint8Array, key: Uint8Array) => Uint8Array;
    crypto_secretbox_open_easy: (ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array) => Uint8Array;
    crypto_pwhash: (keylen: number, password: string, salt: Uint8Array, opslimit: number, memlimit: number, alg: number) => Uint8Array;
    crypto_pwhash_SALTBYTES: number;
    crypto_pwhash_OPSLIMIT_INTERACTIVE: number;
    crypto_pwhash_MEMLIMIT_INTERACTIVE: number;
    crypto_pwhash_ALG_ARGON2ID: number;
    crypto_secretbox_KEYBYTES: number;
    crypto_secretbox_NONCEBYTES: number;
    randombytes_buf: (length: number) => Uint8Array;
    to_base64: (data: Uint8Array) => string;
    from_base64: (str: string) => Uint8Array;
    from_string: (str: string) => Uint8Array;
    to_string: (data: Uint8Array) => string;
  }

  const sodium: Sodium;
  export = sodium;
}