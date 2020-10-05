include "../node_modules/circomlib/circuits/escalarmulany.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

template ElGamalDecrypt() {
    signal input c1[2];
    signal input c2[2];
    signal input xIncrement;
    signal private input privKey;
    signal output out;

    // Convert private key to bits
    component privKeyBits = Num2Bits(253);
    privKeyBits.in <== privKey;
    
    // c1x
    component c1x = EscalarMulAny(253);
    for (var i = 0; i < 253; i ++) {
        c1x.e[i] <== privKeyBits.out[i];
    }
    c1x.p[0] <== c1[0];
    c1x.p[1] <== c1[1];

    // c1 ** -1
    signal c1xInverseX;
    c1xInverseX <== 0 - c1x.out[0];

    // (c1 ** -1) * c2 (multiplicative notation)
    component decryptedPoint = BabyAdd();
    decryptedPoint.x1 <== c1xInverseX;
    decryptedPoint.y1 <== c1x.out[1];
    decryptedPoint.x2 <== c2[0];
    decryptedPoint.y2 <== c2[1];

    out <== decryptedPoint.xout - xIncrement;
}
