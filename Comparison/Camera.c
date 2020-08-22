#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <sys/time.h>
LweSample * Encrypt16BitInteger(int16_t num, TFheGateBootstrappingSecretKeySet* key, TFheGateBootstrappingParameterSet* params) {
    LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(16, params);
    for (int i=0; i<16; i++) {
        bootsSymEncrypt(&ciphertext[i], (num>>i)&1, key);
    }
    return ciphertext;
}

int main() {
    //generate a keyset
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = { 314, 1592, 657 };
    struct timeval tval_before_1, tval_after_1, tval_result_1;
    gettimeofday(&tval_before_1, NULL);
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    //export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);
    gettimeofday(&tval_after_1, NULL);
    timersub(&tval_after_1, &tval_before_1, &tval_result_1);
    printf("The Initialization Took: %ld.%06ld Seconds\n", (long int)tval_result_1.tv_sec, (long int)tval_result_1.tv_usec);
    printf("Please Enter the numbers a, b and theta:\n");
    int16_t plain_a;
    int16_t plain_b;
    int16_t plain_theta;
    scanf("%hd %hd %hd", &plain_a, &plain_b, &plain_theta);
    LweSample* encrypted_a = Encrypt16BitInteger(plain_a, key, params);
    LweSample* encrypted_b = Encrypt16BitInteger(plain_b, key, params);
    LweSample* encrypted_theta = Encrypt16BitInteger(plain_theta, key, params);
    printf("Hi there! Today, I will ask the alarm sensor what whether the difference between %d and %d is larger than %d\n", plain_a, plain_b, plain_theta);
    struct timeval tval_before, tval_after, tval_result;
    gettimeofday(&tval_before, NULL);
    //export the 2x16 ciphertexts to a file (for the cloud)
    FILE* cloud_data = fopen("cloud.data","wb");
    for (int i=0; i<16; i++)
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &encrypted_a[i], params);
    for (int i=0; i<16; i++)
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &encrypted_b[i], params);
    for (int i=0; i<16; i++)
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &encrypted_theta[i], params);
    fclose(cloud_data);
    //clean up all pointers
    gettimeofday(&tval_after, NULL);
    timersub(&tval_after, &tval_before, &tval_result);
    printf("The Encrption Took: %ld.%06ld Seconds\n", (long int)tval_result.tv_sec, (long int)tval_result.tv_usec);
    delete_gate_bootstrapping_ciphertext_array(16, encrypted_a);
    delete_gate_bootstrapping_ciphertext_array(16, encrypted_b);
    delete_gate_bootstrapping_ciphertext_array(16, encrypted_theta);
    //clean up all pointers
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

}
