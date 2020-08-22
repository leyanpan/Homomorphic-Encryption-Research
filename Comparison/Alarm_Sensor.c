#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <sys/time.h>

// elementary full comparator gate that is used to compare the i-th bit:
//   input: ai and bi the i-th bit of a and b
//          lsb_carry: the result of the comparison on the lowest bits
//   algo: if (a==b) return lsb_carry else return a
//   2 gates total
void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    bootsXNOR(tmp, a, b, bk);
    bootsMUX(result, tmp, lsb_carry, a, bk);
}

// returns a > b
// 2 * nb_bits + 2 gates total
void Compare(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);

    //initialize the carry to 0
    bootsCONSTANT(&tmps[0], 0, bk);
    //run the elementary comparator gate n times
    for (int i=0; i<nb_bits; i++) {
        compare_bit(&tmps[0], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    }
    bootsCOPY(result, &tmps[0], bk);
}


// Elementary One Bit Adder
// Input: a and b the two bit to add together
//        cin the carry
// Output: result = the result
//         cout = the carry out
// 5 gates total
void oneBitAdder(LweSample* result, LweSample* cout, const LweSample* a, const LweSample* b, const LweSample* cin, const TFheGateBootstrappingCloudKeySet* bk) {
    bootsXOR(result, a, b, bk);
    bootsXOR(result, result, cin, bk);
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    bootsOR(&tmps[0], b, cin, bk);
    bootsAND(&tmps[1], b, cin, bk);
    bootsMUX(cout, a, &tmps[0], &tmps[1], bk);
    delete_gate_bootstrapping_ciphertext_array(2, tmps);
}

// 5 * nb_bits + 1 gates total
void Adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* tmp = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    bootsCONSTANT(tmp, 0, bk);
    for (int i = 0; i < nb_bits; i++) {
        oneBitAdder(&result[i], tmp, &a[i], &b[i], tmp, bk);
    }
    delete_gate_bootstrapping_ciphertext_array(1, tmp);
}

// 16 * nb_bits + 9
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

int main() {

    //reads the cloud key from file
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = bk->params;

    //read the 2x16 ciphertexts
    LweSample* a = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* b = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* theta = new_gate_bootstrapping_ciphertext_array(16, params);

    //reads the 2x16 ciphertexts from the cloud file
    FILE* cloud_data = fopen("cloud.data","rb");
    for (int i=0; i<16; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &a[i], params);
    for (int i=0; i<16; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &b[i], params);
    for (int i=0; i<16; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &theta[i], params);
    fclose(cloud_data);


    struct timeval tval_before, tval_after, tval_result;
    gettimeofday(&tval_before, NULL);
    //do some operations on the ciphertexts: here, we will compute the
    //minimum of the two
    LweSample* result = new_gate_bootstrapping_ciphertext_array(1, params);
    AlarmSensor(result, a, b, theta, 16, bk);

    gettimeofday(&tval_after, NULL);
    timersub(&tval_after, &tval_before, &tval_result);
    printf("The Comparison Took: %ld.%06ld Seconds\n", (long int)tval_result.tv_sec, (long int)tval_result.tv_usec);
    //export the 32 ciphertexts to a file (for the cloud)
    FILE* answer_data = fopen("answer.data","wb");
    export_gate_bootstrapping_ciphertext_toFile(answer_data, result, params);
    fclose(answer_data);

    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(1, result);
    delete_gate_bootstrapping_ciphertext_array(16, a);
    delete_gate_bootstrapping_ciphertext_array(16, b);
    delete_gate_bootstrapping_ciphertext_array(16, theta);
    delete_gate_bootstrapping_cloud_keyset(bk);

}
