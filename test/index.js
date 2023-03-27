/* eslint-disable max-len */
import assert from 'assert';
import esmock from 'esmock';
import fs from 'fs/promises';

const {
  entropyToMnemonic,
  generateMnemonic,
  mnemonicToEntropy,
  mnemonicToSeed,
  mnemonicToSeedHex,
  validateMnemonic,
} = await esmock('../index.js', {
  randombytes: (size) => {
    return Buffer.from('qwertyuiopasdfghjklzxcvbnm[];,./'.slice(0, size));
  },
});

const wordlists = {
  english: JSON.parse(await fs.readFile('./wordlists/en.json', 'utf8')),
  custom: JSON.parse(await fs.readFile('./test/wordlist.json', 'utf8')),
};

const vectors = JSON.parse(await fs.readFile('./test/vectors.json', 'utf8'));

describe('BIP39', () => {
  describe('mnemonicToSeedHex', function() {
    this.timeout(20000);

    vectors.english.forEach((v, i) => {
      it('works for tests vector ' + i, async () => {
        assert.strictEqual(await mnemonicToSeedHex(v[1], 'TREZOR'), v[2]);
      });
    });
  });

  describe('mnemonicToEntropy', () => {
    vectors.english.forEach((v, i) => {
      it('works for tests vector ' + i, () => {
        assert.equal(mnemonicToEntropy(v[1]).toString('hex'), v[0]);
      });
    });

    vectors.custom.forEach((v, i) => {
      it('works for custom test vector ' + i, () => {
        assert.equal(mnemonicToEntropy(v[1], wordlists.custom).toString('hex'), v[0]);
      });
    });
  });

  describe('entropyToMnemonic', () => {
    vectors.english.forEach((v, i) => {
      it('works for tests vector ' + i, () => {
        assert.equal(entropyToMnemonic(v[0]), v[1]);
      });
    });

    vectors.custom.forEach((v, i) => {
      it('works for custom test vector ' + i, () => {
        assert.equal(entropyToMnemonic(v[0], wordlists.custom), v[1]);
      });
    });
  });

  describe('generateMnemonic', () => {
    vectors.english.forEach((v, i) => {
      it('works for tests vector ' + i, () => {
        function rng() { return Buffer.from(v[0], 'hex'); }

        assert.equal(generateMnemonic(undefined, rng), v[1]);
      });
    });

    it('can vary generated entropy bit length', () => {
      const mnemonic = generateMnemonic(96);
      const words = mnemonic.split(' ');

      assert.equal(words.length, 9);
    });

    it('defaults to randombytes for the RNG', () => {
      assert.equal(generateMnemonic(32), 'imitate robot frequent');
    });

    it('allows a custom RNG to be used', () => {
      const rng = function(size) {
        const buffer = Buffer.alloc(size);
        buffer.fill(4); // guaranteed random
        return buffer;
      };

      const mnemonic = generateMnemonic(64, rng);
      assert.equal(mnemonic, 'advice cage absurd amount doctor act');
    });

    it('adheres to a custom wordlist', () => {
      const rng = function(size) {
        const buffer = Buffer.alloc(size);
        buffer.fill(4); // guaranteed random
        return buffer;
      };

      const mnemonic = generateMnemonic(64, rng, wordlists.custom);
      assert.equal(mnemonic, 'adv1c3 cag3 ab5urd am0unt d0ct0r act');
    });
  });

  describe('validateMnemonic', () => {
    vectors.english.forEach((v, i) => {

      it('passes check ' + i, () => {
        assert(validateMnemonic(v[1]));
      });
    });

    describe('with a custom wordlist', () => {
      vectors.custom.forEach((v, i) => {

        it('passes custom check ' + i, () => {
          assert(validateMnemonic(v[1], wordlists.custom));
        });
      });
    });

    it('fails for mnemonics of wrong length', () => {
      assert(!validateMnemonic('sleep kitten'));
      assert(!validateMnemonic('sleep kitten sleep kitten sleep kitten'));
    });

    it('fails for mnemonics that contains words not from the word list', () => {
      assert(!validateMnemonic('turtle front uncle idea crush write shrug there lottery flower risky shell'));
    });

    it('fails for mnemonics of invalid checksum', () => {
      assert(!validateMnemonic('sleep kitten sleep kitten sleep kitten sleep kitten sleep kitten sleep kitten'));
    });
  });

  describe('utf8 passwords', () => {
    vectors.japanese.forEach((v) => {
      it ('creates the correct seed', async () => {
        const utf8Password = '㍍ガバヴァぱばぐゞちぢ十人十色';
        assert.equal(await mnemonicToSeedHex(v[1], utf8Password), v[2]);
      });

      it ('works with already normalized password', async () => {
        const normalizedPassword = 'メートルガバヴァぱばぐゞちぢ十人十色';
        assert.equal(await mnemonicToSeedHex(v[1], normalizedPassword), v[2]);
      });
    });
  });

  describe('Examples in readme', async () => {
    let mnemonic = entropyToMnemonic('133755ff'); // hex input, defaults to BIP39 English word list
    // 'basket rival lemon'
    assert.ok((/^\w+ \w+ \w+$/).test(mnemonic));

    const temp = mnemonicToEntropy(mnemonic); // hex input, defaults to BIP39 English word list
    // '133755ff'
    assert.equal(temp.toString('hex'), '133755ff');

    // Generate a random mnemonic using crypto.randomBytes
    mnemonic = generateMnemonic(); // strength defaults to 128 bits
    //'bench maximum balance appear cousin negative muscle inform enjoy chief vocal hello'
    assert.ok(/^(\w+ ){11}\w+$/.test(mnemonic));

    const str = await mnemonicToSeedHex('basket actual');
    //'5cf2d4a8b0355e90295bdfc565a022a409af063d5365bb57bf74d9528f494bfa4400f53d8349b80fdae44082d7f9541e1dba2b003bcfec9d0d53781ca676651f'
    assert.equal(str, '5cf2d4a8b0355e90295bdfc565a022a409af063d5365bb57bf74d9528f494bfa4400f53d8349b80fdae44082d7f9541e1dba2b003bcfec9d0d53781ca676651f');

    const buff = await mnemonicToSeed('basket actual');
    const fiveC = 5*16+12;
    assert.equal(buff[0], fiveC);
    // <Buffer 5c f2 d4 a8 b0 35 5e 90 29 5b df c5 65 a0 22 a4 09 af 06 3d 53 65 bb 57 bf 74 d9 52 8f 49 4b fa 44 00 f5 3d 83 49 b8 0f da e4 40 82 d7 f9 54 1e 1d ba 2b ...>

    let bool = validateMnemonic(mnemonic);
    // true
    assert.ok(bool);

    bool = validateMnemonic('basket actual');
    // false
    assert.ok(! bool);
  });
});
