import { encrypt, decrypt, rerandomize, ElGamalCiphertext } from '../'
import { genPrivKey, genPubKey, genRandomSalt } from 'maci-crypto'

describe('ElGamal encryption and decryption', () => {
    const plaintext = genRandomSalt()
    const privKey = genPrivKey()
    const pubKey = genPubKey(privKey)

    let ciphertext: ElGamalCiphertext

    it('Should encrypt and decrypt a plaintext', () => {
        ciphertext = encrypt(plaintext, pubKey)
        const decrypted = decrypt(privKey, ciphertext)
        if (decrypted.toString() !== plaintext.toString()) {
            debugger
        }
        expect(decrypted.toString()).toEqual(plaintext.toString())
    })

    it('Should decrypt to the same value after rerandomization', () => {
        const rerandomized = rerandomize(pubKey, ciphertext)

        expect(rerandomized.xIncrement.toString()).toEqual(ciphertext.xIncrement.toString())
        expect(rerandomized.c1.x.toString()).not.toEqual(ciphertext.c1.x.toString())
        expect(rerandomized.c1.y.toString()).not.toEqual(ciphertext.c1.y.toString())
        expect(rerandomized.c2.x.toString()).not.toEqual(ciphertext.c2.x.toString())
        expect(rerandomized.c2.x.toString()).not.toEqual(ciphertext.c2.x.toString())

        const decrypted = decrypt(privKey, rerandomized)
        expect(decrypted.toString()).toEqual(plaintext.toString())
    })

    it('Stress test', () => {
        const MAX = 10
        expect.assertions(MAX)
        for (let i = 0; i < MAX; i ++) {
            const plaintext = genRandomSalt()
            const privKey = genPrivKey()
            const pubKey = genPubKey(privKey)
            const ciphertext = encrypt(plaintext, pubKey)
            const decrypted = decrypt(privKey, ciphertext)
            expect(decrypted.toString()).toEqual(plaintext.toString())
        }
    })
})
