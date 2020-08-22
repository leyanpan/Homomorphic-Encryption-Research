#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <sys/time.h>
int main() {

    //reads the cloud key from file
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;

    //read the 16 ciphertexts of the result
    LweSample* answer = new_gate_bootstrapping_ciphertext_array(1, params);

    //import the 32 ciphertexts from the answer file
    FILE* answer_data = fopen("answer.data","rb");
    import_gate_bootstrapping_ciphertext_fromFile(answer_data, answer, params);
    struct timeval tval_before, tval_after, tval_result;
    gettimeofday(&tval_before, NULL);

    int ans = bootsSymDecrypt(answer, key);
    gettimeofday(&tval_after, NULL);
    timersub(&tval_after, &tval_before, &tval_result);
    printf("The Decryption Took: %ld.%06ld Seconds\n", (long int)tval_result.tv_sec, (long int)tval_result.tv_usec);
    printf("And the result is: %d\n",ans);
    printf("I hope you remember what was the question!\n");

    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(16, answer);
    delete_gate_bootstrapping_secret_keyset(key);
}
