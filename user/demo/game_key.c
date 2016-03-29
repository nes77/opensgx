#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sgx-lib.h>

typedef struct _score_data {
    uint64_t high_score;
    uint8_t checksum;
    uint8_t padding[7];
} score_data;

#define KEY_SIZE 16
// Hackish way to get 128-bit aligned 128 byte region of memory without OS help.
typedef struct { uint8_t data[KEY_SIZE]; uint8_t* aligned_ptr; } sgx_keydata __attribute__ ((aligned (16)));

static void print_key(sgx_keydata* ptr) {
    char hex_representation[KEY_SIZE*2 + 1] = {'\0'};
    for(int i = 0; i < KEY_SIZE; i++) {
        char byte_hex_rep[16] = {'\0'};
        sprintf(byte_hex_rep, "%02hhX", (unsigned char) ptr->aligned_ptr[i]);
        strcat(hex_representation, byte_hex_rep);
    }

    puts("Key is:");
    puts(hex_representation);

}

// Aligns the pointer in the key struct, and initializes it with the EGETKEY instruction.
static void sgx_keydata_init(sgx_keydata* ptr) {
    uint8_t* original_ptr;
    if (ptr == NULL) {
        return;
    }

    original_ptr = ptr->data;
    //original_ptr = (uint8_t*)((((uint64_t) ptr) & ~127) + 128);
    ptr->aligned_ptr = original_ptr;

//    sigstruct_t* sigstruct;
//    sigstruct = sgx_load_sigstruct("user/demo/hello.conf");

    keyrequest_t keyrequest;
//    keyrequest.isvsvn = sigstruct->isvSvn;
//    keyrequest.keypolicy.mrenclave = 1;
    keyrequest.keyname = SEAL_KEY;

    sgx_getkey(&keyrequest, ptr->aligned_ptr);

    print_key(ptr);
    
}

// If rdrand can be controlled, then this might be vulnerable to attack.
// It's unclear as to whether or not the libc rand() call is in userspace or the enclave
// with opensgx.
static inline uint32_t psirand() {
    uint32_t y;
    __asm__ __volatile__ ("rdrand %0" : "=r" (y));
    return y;
}

// Simple parity checker. Not terribly secure, but used for the same reason as the crappy
// random number generator
static uint8_t hash(unsigned char* data, size_t len) {
    uint8_t h = 0;
    size_t i = 0;

    if (data == NULL) {
        return h;
    } else {
        for (i = 0; i < len; i++) {
            h ^= data[i];
        }

        return h;
    }

}

// XTEA cipher; implementation taken from Wikipedia article on XTEA
static void encrypt(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0 = v[0];
    uint32_t v1 = v[1];
    uint32_t sum = 0;
    uint32_t delta = 0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }

    v[0] = v0;
    v[1] = v1;
}

static void decrypt(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0];
    uint32_t v1=v[1];
    uint32_t delta = 0x9E3779B9;
    uint32_t sum = delta*num_rounds;
    for (i = 0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

static void encrypt_data(sgx_keydata* key, score_data* data, score_data* out) {
    size_t i, v_index, key_index;
    size_t bounded_i;
    uint32_t* data_v_ptr;
    uint32_t* key_part_ptr;
    uint32_t v[2];
    uint32_t key_part[4];
    uint8_t* key_ptr = key->aligned_ptr;
    uint32_t* out_ptr = (uint32_t*) out;

    data_v_ptr = (uint32_t*) data;
    key_part_ptr = (uint32_t*) key_ptr;

    for (i = 0, bounded_i = 0; i < sizeof(score_data)/sizeof(uint32_t);
            i += 2, bounded_i = (bounded_i + 4) % ((KEY_SIZE)/sizeof(uint32_t))) {

        for (v_index = 0; v_index < 2; v_index++) {
            v[v_index] = data_v_ptr[i + v_index];
        }

        for (key_index = 0; key_index < 4; key_index++) {
            key_part[key_index] = key_part_ptr[bounded_i + key_index];
        }

        encrypt(64, v, key_part);

        out_ptr[i] = v[0];
        out_ptr[i + 1] = v[1];
    }

}

static void decrypt_data(sgx_keydata* key, score_data* data, score_data* out) {
    size_t i, v_index, key_index;
    size_t bounded_i;
    uint32_t* data_v_ptr;
    uint32_t* key_part_ptr;
    uint32_t v[2];
    uint32_t key_part[4];
    uint8_t* key_ptr = key->aligned_ptr;
    uint32_t* out_ptr = (uint32_t*) out;

    data_v_ptr = (uint32_t*) data;
    key_part_ptr = (uint32_t*) key_ptr;

    for (i = 0, bounded_i = 0; i < sizeof(score_data)/sizeof(uint32_t);
            i += 2, bounded_i = (bounded_i + 4) % (KEY_SIZE/sizeof(uint32_t))) {

        for (v_index = 0; v_index < 2; v_index++) {
            v[v_index] = data_v_ptr[i + v_index];
        }

        for (key_index = 0; key_index < 4; key_index++) {
            key_part[key_index] = key_part_ptr[bounded_i + key_index];
        }

        decrypt(64, v, key_part);

        out_ptr[i] = v[0];
        out_ptr[i + 1] = v[1];
    }

}

void enclave_main() {
    uint64_t roll, checksum;
    score_data high_score_file_data;
    score_data decrypted_highscore_data;
    sgx_keydata key;
    FILE* high_score_file;
    size_t byte_num;

    const char* high_score_filename = "highscore.game";
    const char* prompt = "Welcome to the game!\nRolling a die...";
    const char* result = "You rolled a %llx!\n";
    const char* high_score_prompt = "The high score is %llx.\n";
    const char* new_high_score = "New high score!";
    const char* error = "An error occurred...";

    // Std library calls usually put their arguments in a section of memory that will be acessible to the OS
    // This does that, calls AEX (asynchronous exit) targeting a preset section of code (the trampoline)
    // which takes actions accordingly. Once the call is completed, ERESUME is called, and the enclave resumes
    // execution.
    //
    // Enclave data/state is stored in an encrypted stack frame during this exit
    puts(prompt);   

    // Not golden random number generating, but I want something that is executed inside the enclave.
    roll = psirand();

    printf(result, roll);

    sgx_keydata_init(&key);
    
    high_score_file = fopen(high_score_filename, "a");

    if (high_score_file == NULL) {
        puts("Can't open file. Giving up...\n");
        sgx_exit(NULL);
    }

    byte_num = fclose(high_score_file);

    if (byte_num != 0) {
        puts(error);
    }

    high_score_file = fopen(high_score_filename, "rb+");

    if (high_score_file == NULL) {
        puts("Can't open file. Giving up...\n");
        sgx_exit(NULL);
    } 

    byte_num = fread(&high_score_file_data, sizeof(score_data), 1, high_score_file);

    if (!(byte_num == 1)) {
         puts("Could not read from highscore file (happens on first use)... resetting.\n");
    } else {
        // decrypt and verify data
        decrypt_data(&key, &high_score_file_data, &decrypted_highscore_data);
        checksum = hash((uint8_t*)&(decrypted_highscore_data.high_score), sizeof(uint64_t));

        if (checksum != (uint64_t) decrypted_highscore_data.checksum) {
            puts("Bad highscore file. Resetting...\n");
            decrypted_highscore_data.checksum = 0;
            decrypted_highscore_data.high_score = 0;
        }
       
    }

    if (roll > decrypted_highscore_data.high_score) {
        decrypted_highscore_data.high_score = roll;
        decrypted_highscore_data.checksum = hash((uint8_t*)&roll, sizeof(uint64_t));
        puts(new_high_score);
    }

    encrypt_data(&key, &decrypted_highscore_data, &high_score_file_data);

    byte_num = fseek(high_score_file, 0, SEEK_SET);

    if (byte_num != 0) {
        puts(error);
        sgx_exit(NULL);
    }

    byte_num = fwrite(&high_score_file_data, sizeof(score_data), 1, high_score_file);

    if (byte_num != 1) {
        //printf("%lu, %lu\n", byte_num, sizeof(score_data));
        puts(error);
        sgx_exit(NULL);
    }

    printf(high_score_prompt, decrypted_highscore_data.high_score);

    fflush(high_score_file);
    if (fclose(high_score_file) != 0) {
        puts("An error occurred while closing the file. Your game may not have been saved.\n");
    }


    fflush(stdout);
    sgx_exit(NULL);
}
