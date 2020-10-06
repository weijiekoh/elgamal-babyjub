include "../node_modules/circomlib/circuits/escalarmulany.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/*
 * Performs rerandomization on an ElGamal ciphertext.
 * The comments and signal names follow the symbols used here:
 * https://ethresear.ch/t/maci-anonymization-using-rerandomizable-encryption/7054
 *
 * c1, c2: The existing ciphertext
 * d1, d2: The rerandomized ciphertext
 * z:      The random value (randomVal)
 * pubKey: The public key under which the existing ciphertext was encrypted
 * g:      A generator
 *
 * d1 = (g ** z) * c1
 * d2 = (pk ** z) * c2
 */
template ElGamalReRandomize() {
    signal input c1[2];
    signal input c2[2];
    signal input randomVal;
    signal input pubKey[2];
    signal output d1[2];
    signal output d2[2];

    // Convert randomVal to bits
    component randomValBits = Num2Bits(253);
    randomValBits.in <== randomVal;

    // g ** z
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];
    component gz = EscalarMulFix(253, BASE8);
    for (var i = 0; i < 253; i ++) {
        gz.e[i] <== randomValBits.out[i];
    }

    // (g ** z) * c1
    component d1Adder = BabyAdd();
    d1Adder.x1 <== gz.out[0];
    d1Adder.y1 <== gz.out[1];
    d1Adder.x2 <== c1[0];
    d1Adder.y2 <== c1[1];

    // pubKey ** z
    component pubKeyZ = EscalarMulAny(253);
    for (var i = 0; i < 253; i ++) {
        pubKeyZ.e[i] <== randomValBits.out[i];
    }
    pubKeyZ.p[0] <== pubKey[0];
    pubKeyZ.p[1] <== pubKey[1];

    // (pubKey ** z) * c2
    component d2Adder = BabyAdd();
    d2Adder.x1 <== pubKeyZ.out[0];
    d2Adder.y1 <== pubKeyZ.out[1];
    d2Adder.x2 <== c2[0];
    d2Adder.y2 <== c2[1];

    // Output the rerandomized ciphertext
    d1[0] <== d1Adder.xout;
    d1[1] <== d1Adder.yout;
    d2[0] <== d2Adder.xout;
    d2[1] <== d2Adder.yout;
}
