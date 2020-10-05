jest.setTimeout(90000)
import {
    encodeToMessage,
    decodeMessage,
    Message,
    encrypt,
    decrypt,
    rerandomize,
    ElGamalCiphertext,
    compileAndLoadCircuit,
    executeCircuit,
    getSignalByName,
} from '../'

import {
    genPrivKey,
    genPubKey,
    genRandomSalt,
    formatPrivKeyForBabyJub
} from 'maci-crypto'

import { babyJub } from 'circomlib'

describe('snark circuits', () => {
    const plaintext = genRandomSalt()
    const encoded = encodeToMessage(plaintext)
    const privKey = genPrivKey()
    const pubKey = genPubKey(privKey)
    const ciphertext = encrypt(plaintext, pubKey)

    let decryptCircuit
    let rerandomizeCircuit

    beforeAll(async () => {
        rerandomizeCircuit = await compileAndLoadCircuit('test/rerandomize_test.circom')
        decryptCircuit = await compileAndLoadCircuit('test/decrypt_test.circom')
    })

    it('should decrypt a ciphertext', async () => {
        const circuitInputs = {
            c1: [ciphertext.c1.x, ciphertext.c1.y],
            c2: [ciphertext.c2.x, ciphertext.c2.y],
            xIncrement: ciphertext.xIncrement,
            privKey: formatPrivKeyForBabyJub(privKey),
        }

        const witness = await executeCircuit(decryptCircuit, circuitInputs)
        const out = getSignalByName(decryptCircuit, witness, 'main.out').toString() 
        expect(out.toString()).toEqual(plaintext.toString())
    })

    it('should rerandomize a ciphertext', async () => {
        const randomVal = formatPrivKeyForBabyJub(genRandomSalt())
        const rerandomized = rerandomize(pubKey, ciphertext, randomVal)

        const circuitInputs = {
            c1: [ciphertext.c1.x, ciphertext.c1.y],
            c2: [ciphertext.c2.x, ciphertext.c2.y],
            randomVal,
            pubKey,
        }
        const witness = await executeCircuit(rerandomizeCircuit, circuitInputs)
        const d1X = getSignalByName(rerandomizeCircuit, witness, 'main.d1[0]').toString() 
        const d1Y = getSignalByName(rerandomizeCircuit, witness, 'main.d1[1]').toString() 
        const d2X = getSignalByName(rerandomizeCircuit, witness, 'main.d2[0]').toString() 
        const d2Y = getSignalByName(rerandomizeCircuit, witness, 'main.d2[1]').toString() 

        expect(d1X.toString()).toEqual(rerandomized.c1.x.toString())
        expect(d1Y.toString()).toEqual(rerandomized.c1.y.toString())
        expect(d2X.toString()).toEqual(rerandomized.c2.x.toString())
        expect(d2Y.toString()).toEqual(rerandomized.c2.y.toString())

        const circuitInputs2 = {
            c1: [rerandomized.c1.x, rerandomized.c1.y],
            c2: [rerandomized.c2.x, rerandomized.c2.y],
            xIncrement: ciphertext.xIncrement,
            privKey: formatPrivKeyForBabyJub(privKey),
        }

        const witness2 = await executeCircuit(decryptCircuit, circuitInputs2)
        const out = getSignalByName(decryptCircuit, witness2, 'main.out').toString() 
        expect(out.toString()).toEqual(plaintext.toString())
    })
})
