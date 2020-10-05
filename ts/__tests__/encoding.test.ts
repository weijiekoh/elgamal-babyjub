import { encodeToMessage, decodeMessage, Message } from '../'
import { babyJub } from 'circomlib'
import { genRandomSalt } from 'maci-crypto'

describe('Elliptic curve message encoding and decoding', () => {
    const plaintext = genRandomSalt()
    const encoded = encodeToMessage(plaintext)

    it('Should convert a value to a valid BabyJub point', () => {
        const point = [encoded.point.x, encoded.point.y]
        const valid = babyJub.inCurve(point)
        expect(valid).toBeTruthy()

        const packedPoint = babyJub.packPoint(point)
        const unpackedPoint = babyJub.unpackPoint(packedPoint)
    })

    it('Should convert the BabyJub point back to the same value', () => {
        const decoded = decodeMessage(encoded)
        expect(decoded.toString()).toEqual(plaintext.toString())
    })

    it('Stress test', () => {
        const MAX = 10
        expect.assertions(MAX)
        for (let i = 0; i < MAX; i ++) {
            const plaintext = genRandomSalt()
            const encoded = encodeToMessage(plaintext)
            const decoded = decodeMessage(encoded)
            expect(decoded.toString()).toEqual(plaintext.toString())
        }
    })
})
