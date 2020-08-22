#include <stdio.h>
typedef int LweSample;
void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp) {
    //bootsXNOR(tmp, a, b, bk);
    tmp[0] = ! (a[0]^b[0]);
    //bootsMUX(result, tmp, lsb_carry, a, bk);
    result[0] = tmp[0] ? lsb_carry[0] : a[0];
}

// returns a > b
LweSample* Compare(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    //LweSample* tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    LweSample tmps[2];
    //initialize the carry to 0
    //bootsCONSTANT(&tmps[0], 0, bk);
    tmps[0] = 0;
    //run the elementary comparator gate n times
    for (int i = 0; i<nb_bits; i++) {
        compare_bit(&tmps[0], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    }
    return tmps;
}


// Elementary One Bit Adder
// Input: a and b the two bit to add together
//        cin the carry
// Output: result = the result
//         cout = the carry out
void oneBitAdder(LweSample* result, LweSample* cout, const LweSample* a, const LweSample* b, const LweSample* cin, const TFheGateBootstrappingCloudKeySet* bk) {
    bootsXOR(result, a, b, bk);
    bootsXOR(result, result, cin, bk);
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    bootsOR(&tmps[0], b, cin, bk);
    bootsAND(&tmps[1], b, cin, bk);
    bootsMUX(cout, a, &tmps[0], &tmps[1], bk);
    delete_gate_bootstrapping_ciphertext_array(2, tmps);
}

void Adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* tmp = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    bootsCONSTANT(tmp, 0, bk);
    for (int i = 0; i < nb_bits; i++) {
        oneBitAdder(&result[i], tmp, &a[i], &b[i], tmp, bk);
    }
    delete_gate_bootstrapping_ciphertext_array(1, tmp);
}


void AlarmSensor(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* theta, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    //Compare a with b
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(3, bk->params);
    Compare(&tmps[0], a, b, nb_bits, bk);
    // b + theta < a
    LweSample* bplustheta = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    Adder(bplustheta, b, theta, nb_bits, bk);
    Compare(&tmps[1], a, bplustheta, nb_bits, bk);
    // a + theta < b
    LweSample* aplustheta = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    Adder(aplustheta, a, theta, nb_bits, bk);
    Compare(&tmps[2], b, aplustheta, nb_bits, bk);
    bootsMUX(result, &tmps[0], &tmps[1], &tmps[2], bk);
    delete_gate_bootstrapping_ciphertext_array(3, tmps);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, bplustheta);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, aplustheta);
}
