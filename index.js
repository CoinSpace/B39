import createHash from 'create-hash';
import { pbkdf2 } from 'pbkdf2';
import randomBytes from 'randombytes';

import DEFAULT_WORDLIST from './wordlists/en.js';

export function mnemonicToSeed(mnemonic, password) {
  const mnemonicBuffer = Uint8Array.from(Buffer.from(normalize(mnemonic), 'utf8'));
  const saltBuffer = Uint8Array.from(Buffer.from(salt(normalize(password)), 'utf8'));
  return new Promise((resolve, reject) => {
    pbkdf2(mnemonicBuffer, saltBuffer, 2048, 64, 'sha512', (err, derivedKey) => {
      if (err) {
        return reject(err);
      }
      return resolve(derivedKey);
    });
  });
}

export function mnemonicToSeedHex(mnemonic, password) {
  return mnemonicToSeed(mnemonic, password)
    .then((seed) => seed.toString('hex'));
}

export function mnemonicToEntropy(mnemonic, wordlist = DEFAULT_WORDLIST) {
  const words = normalize(mnemonic).split(' ');
  if (words.length % 3 !== 0) {
    throw new Error('Invalid mnemonic');
  }

  const belongToList = words.every((word) => {
    return wordlist.indexOf(word) > -1;
  });

  if (!belongToList) {
    throw new Error('Invalid mnemonic');
  }

  // convert word indices to 11 bit binary strings
  const bits = words.map((word) => {
    const index = wordlist.indexOf(word);
    return lpad(index.toString(2), '0', 11);
  }).join('');

  // split the binary string into ENT/CS
  const dividerIndex = Math.floor(bits.length / 33) * 32;
  const entropy = bits.slice(0, dividerIndex);
  const checksum = bits.slice(dividerIndex);

  // calculate the checksum and compare
  const entropyBytes = entropy.match(/(.{1,8})/g).map(binaryToByte);
  const entropyBuffer = Buffer.from(entropyBytes);
  const newChecksum = checksumBits(entropyBuffer);

  if (newChecksum !== checksum) {
    throw new Error('Invalid mnemonic checksum');
  }

  return entropyBuffer;
}

export function entropyToMnemonic(entropy, wordlist = DEFAULT_WORDLIST) {
  if (!Buffer.isBuffer(entropy)) {
    entropy = Buffer.from(entropy, 'hex');
  }
  const entropyBits = bytesToBinary(Array.from(entropy));
  const checksum = checksumBits(entropy);

  const bits = entropyBits + checksum;
  const chunks = bits.match(/(.{1,11})/g);

  const words = chunks.map((binary) => {
    const index = binaryToByte(binary);
    return wordlist[index];
  });

  return words.join(' ');
}

export function generateMnemonic(strength = 128, rng = randomBytes, wordlist = DEFAULT_WORDLIST) {
  const entropy = Buffer.from(rng(strength / 8));
  return entropyToMnemonic(entropy, wordlist);
}

export function validateMnemonic(mnemonic, wordlist) {
  try {
    mnemonicToEntropy(mnemonic, wordlist);
  } catch (e) {
    return false;
  }
  return true;
}

export { DEFAULT_WORDLIST };

//=========== helper methods ========

function normalize(str) {
  return (str || '').normalize('NFKD');
}

function checksumBits(entropyBuffer) {
  const hash = createHash('sha256').update(entropyBuffer).digest();

  // Calculated constants from BIP39
  const ENT = entropyBuffer.length * 8;
  const CS = ENT / 32;

  return bytesToBinary([].slice.call(hash)).slice(0, CS);
}

function salt(password) {
  return 'mnemonic' + (password || '');
}

function binaryToByte(bin) {
  return parseInt(bin, 2);
}

function bytesToBinary(bytes) {
  return bytes.map((x) => {
    return lpad(x.toString(2), '0', 8);
  }).join('');
}

function lpad(str, padString, length) {
  while (str.length < length) {
    str = padString + str;
  }
  return str;
}
