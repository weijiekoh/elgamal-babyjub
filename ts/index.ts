import * as assert from 'assert'
import * as path from 'path'
const circom = require('circom')
import { babyJub } from 'circomlib'
import {
    genPubKey,
    genPrivKey,
    formatPrivKeyForBabyJub,
    PubKey,
    PrivKey,
    genRandomSalt,
} from 'maci-crypto'
import {
    executeCircuit,
    getSignalByName,
    compileAndLoadCircuit,
} from 'maci-circuits'

const F = babyJub.F

interface BabyJubPoint {
    x: BigInt,
    y: BigInt,
}

interface Message {
    point: BabyJubPoint,
    xIncrement: BigInt,
}

interface ElGamalCiphertext {
    c1: BabyJubPoint;
    c2: BabyJubPoint;
    xIncrement: BigInt;
}

/*
 * Converts an arbitrary BigInt, which must be less than the BabyJub field
 * size, into a Message. Each Message has a BabyJub curve point, and an
 * x-increment. Since not all values in the BabyJub field have a corresponding
 * y-value in the curve, we have to find the smallest x-increment which, when
 * added to the original BigInt, has a corresponding y-Value in the curve.
 *
 * @param original The value to encode. It must be less than the BabyJub field
 *                 size.
 */
const encodeToMessage = (
   original: BigInt
): Message => {
    const randomVal = genPrivKey()
    const randomPoint = genPubKey(randomVal)

    assert(babyJub.inSubgroup(randomPoint))

    const xIncrement = F.e(F.sub(randomPoint[0], original))

    assert(xIncrement >= BigInt(0))

    const xVal = randomPoint[0]
    const yVal = randomPoint[1]

    const point: BabyJubPoint = { x: xVal, y: yVal }

    return { point, xIncrement }
}

/*
 * Converts a Message into the original value.
 * The original value is the x-value of the BabyJub point minus the x-increment.
 * @param message The message to convert.
 */
const decodeMessage = (message: Message): BigInt => {
    const decoded = BigInt(
        F.e(
            F.sub(message.point.x, message.xIncrement),
        )
    )
    assert(decoded >= BigInt(0))
    assert(decoded < babyJub.p)

    return decoded
}

/*
 * Encrypts a plaintext such that only the owner of the specified public key
 * may decrypt it.
 * @param plaintext An arbitrary value which must be within the BabyJub field
 * @param pubKey The recepient's public key
 * @param randomVal A random value y used along with the private key to
 *                  generate the ciphertext
 */
const encrypt = (
    plaintext: BigInt,
    pubKey: PubKey,
    randomVal: BigInt = genRandomSalt(),
): ElGamalCiphertext => {
    const message: Message = encodeToMessage(plaintext)

    const c1Point = babyJub.mulPointEscalar(babyJub.Base8, randomVal)

    const pky = babyJub.mulPointEscalar(pubKey, randomVal)
    const c2Point = babyJub.addPoint(
        [message.point.x, message.point.y],
        pky,
    )

    return {
        c1: { x: c1Point[0], y: c1Point[1] },
        c2: { x: c2Point[0], y: c2Point[1] },
        xIncrement: message.xIncrement,
    }
}

/*
 * Decrypts a ciphertext using a private key.
 * @param privKey The private key
 * @param ciphertext The ciphertext to decrypt
 */
const decrypt = (privKey: PrivKey, ciphertext: ElGamalCiphertext): BigInt => {

    const c1x = babyJub.mulPointEscalar(
        [ciphertext.c1.x, ciphertext.c1.y],
        formatPrivKeyForBabyJub(privKey),
    )

    const c1xInverse = [
        F.e(c1x[0] * BigInt(-1)),
        BigInt(c1x[1]),
    ]

    const decrypted = babyJub.addPoint(
        c1xInverse,
        [ciphertext.c2.x, ciphertext.c2.y],
    )

    return decodeMessage(
        { 
            point: {
                x: decrypted[0],
                y: decrypted[1],
            },
            xIncrement: ciphertext.xIncrement,
        }
    )
}

/*
 * Randomize a ciphertext such that it is different from the original
 * ciphertext but can be decrypted by the same private key.
 * @param pubKey The same public key used to encrypt the original plaintext
 * @param ciphertext The ciphertext to re-randomize.
 * @param randomVal A random value z such that the re-randomized ciphertext
 *                  could have been generated a random value y+z in the first
 *                  place (optional)
 */
const rerandomize = (
    pubKey: PubKey,
    ciphertext: ElGamalCiphertext,
    randomVal: BigInt = genRandomSalt(),
): ElGamalCiphertext => {
    const d1 = babyJub.addPoint(
        babyJub.mulPointEscalar(babyJub.Base8, randomVal),
        [ciphertext.c1.x, ciphertext.c1.y],
    )

    const d2 = babyJub.addPoint(
        babyJub.mulPointEscalar(pubKey, randomVal),
        [ciphertext.c2.x, ciphertext.c2.y],
    )

    return { 
        c1: { x: d1[0], y: d1[1] },
        c2: { x: d2[0], y: d2[1] },
        xIncrement: ciphertext.xIncrement,
    }
}

/*
 * @param circuitPath The subpath to the circuit file (e.g.
 *     test/batchProcessMessage_test.circom)
 */
const compileAndLoadCircuit = async (
    circuitPath: string
) => {

    const circuit = await circom.tester(
        path.join(
            __dirname,
            `../circom/${circuitPath}`,
        ),
    )

    await circuit.loadSymbols()

    return circuit
}

const executeCircuit = async (
    circuit: any,
    inputs: any,
) => {

    const witness = await circuit.calculateWitness(inputs, true)
    await circuit.checkConstraints(witness)
    await circuit.loadSymbols()

    return witness
}

const getSignalByName = (
    circuit: any,
    witness: any,
    signal: string,
) => {

    return witness[circuit.symbols[signal].varIdx]
}

export {
    Message,
    BabyJubPoint,
    ElGamalCiphertext,
    encodeToMessage,
    decodeMessage,
    encrypt,
    decrypt,
    rerandomize,
    compileAndLoadCircuit,
    executeCircuit,
    getSignalByName,
}
