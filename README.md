# ElGamal Decryption and Re-randomization in Typescript and circom

This Typescript library implements ElGamal encryption, decryption, and
re-randomization on the BabyJub curve. It also provides
[`circom`](https://github.com/iden3/circom) circuits for decryption and
re-randomization.

This was written for future implementation of [MACI
anonymization](https://ethresear.ch/t/maci-anonymization-using-rerandomizable-encryption/7054).

## Getting started

Clone this repository, install dependencies, and build the source code:

```bash
git clone git@github.com:weijiekoh/elgamal-babyjub.git &&
cd elgamal-babyjub &&
npm i &&
npm run build
```

Run tests:

```
npm run test
```

## Library functions

### `encodeToMessage`

`encodeToMessage = (original: BigInt): Message`

This function converts an arbitrary value within the BabyJub finite field into
a BabyJub curve point and an `xIncrement` value. It generates a random curve
point within the BabyJub subgroup and computes the difference between its
x-value and the plaintext.

### `encrypt`

`encrypt = (plaintext: BigInt, pubKey: PubKey, randomVal?: BigInt): ElGamalCiphertext`

This function encrypts a single `BigInt` plaintext into a ciphertext. Only the
owner of the private key associated with `pubKey` can decrypt it.

### `decrypt`

`decrypt = (privKey: PrivKey, ciphertext: ElGamalCiphertext): BigInt`

Decrypts a cipertext into the original `BigInt`.

### `rerandomize`

`rerandomize = (pubKey: PubKey, ciphertext: ElGamalCiphertext, randomVal: BigInt = genRandomSalt()): ElGamalCiphertext`

Re-randomizes a ciphertext such that its value changes but can be decrypted to the same plaintext.

The `randomVal` should be specified if one wishes to use the
`ElGamalReRandomize` circuit described below.

## Zero-knowledge circuits

### `ElGamalDecrypt`

Input signals:

- `c1[2]`: The x and y-coordinates of the `c1` value of the ciphertext
- `c2[2]`: The x and y-coordinates of the `c2` value of the ciphertext
- `xIncrement`: The x-increment value of the ciphertext
- `privKey` (private): The private key

Output signals:

- `out`: The original value


### `ElGamalReRandomize`

Input signals:

- `c1[2]`: The x and y-coordinates of the `c1` value of the ciphertext
- `c2[2]`: The x and y-coordinates of the `c2` value of the ciphertext
- `randomVal`: A random value. It must be the same as the one passed to the
               above `rerandomize()` function for both the circuit and
               Typescript function to output the same rerandomized ciphertext.
- `pubKey`: The public key originally used to encrypt the ciphertext

Output signals:

- `d1[2]`: The x and y-coordinates of the `d1` value of the rerandomized ciphertext
- `d2[2]`: The x and y-coordinates of the `d2` value of the rerandomized ciphertext
