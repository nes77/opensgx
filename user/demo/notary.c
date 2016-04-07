#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sgx-lib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_SIZE 16
#define BLOCK_SIZE 4096
#define RSA_BIT_SIZE 2048
#define RSA_BYTE_SIZE RSA_BIT_SIZE/8

#define CLOSE_NOTARY 0
#define SIGN_DATA 1

#define OK 0
#define TOO_BIG 1
#define ERROR 2
#define SENDING 3

#define MAX_FILE_SIZE 64 * 1024
#define BLOCK_DATA_SIZE BLOCK_SIZE - sizeof(uint8_t)
// Hackish way to get 128-bit aligned 128 byte region of memory without OS help.
typedef struct { uint8_t data[KEY_SIZE]; } sgx_keydata __attribute__ ((aligned (16)));

typedef struct {
    uint8_t data[BLOCK_DATA_SIZE];
    uint8_t parity;
} crypto_block;

// Simple parity checker. Not terribly secure, but used for the same reason as the crappy
// random number generator
static uint8_t parity(unsigned char* data, size_t len) {
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

int XXcrypt_data(sgx_keydata* key, uint8_t* in, uint8_t* out, size_t len, int encrypt) {
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    int ret = 0;
    int outlen = 0;
    unsigned char iv[KEY_SIZE] = {0};

    EVP_CipherInit_ex(ctx, EVP_rc4(), NULL, NULL, NULL, encrypt); 

    EVP_CIPHER_CTX_set_key_length(ctx, KEY_SIZE);

    EVP_CipherInit_ex(ctx, NULL, NULL, key->data, iv, encrypt);

    for (size_t i = 0; i < len; i+= KEY_SIZE) {
        if (!EVP_CipherUpdate(ctx, out + i, &outlen, in + i, 16)) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    if (!EVP_CipherFinal_ex(ctx, out, &outlen)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }


    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int encrypt_data(sgx_keydata* key, uint8_t* in, uint8_t* out, size_t len) {
    return XXcrypt_data(key, in, out, len, 1);
}

int decrypt_data(sgx_keydata* key, uint8_t* in, uint8_t* out, size_t len) {
    return XXcrypt_data(key, in, out, len, 0);
}

    
static void print_key(sgx_keydata* ptr) {
    char hex_representation[KEY_SIZE*2 + 1] = {'\0'};
    for(int i = 0; i < KEY_SIZE; i++) {
        char byte_hex_rep[16] = {'\0'};
        sprintf(byte_hex_rep, "%02hhX", (unsigned char) ptr->data[i]);
        strcat(hex_representation, byte_hex_rep);
    }

    puts("Key is:");
    puts(hex_representation);

}

typedef struct {
    uint64_t data[32];
} hash_file_t;

static int gen_hash_file(sgx_keydata* key, const char* filename, char* hash) {
    FILE* out_file = fopen(filename, "w+");
    
    crypto_block* data = calloc(sizeof(crypto_block), 1);
    crypto_block* out = calloc(sizeof(crypto_block), 1);

    uint64_t initial_data[] = {
        0xdeadbeefcafebabe,
        0xcafebabedeadbeef,
        0xc001d00dba5eba11,
        0xca11ab1edeadbea7
    };

    memcpy(data->data, initial_data, 32);
    data->parity = parity(data->data, BLOCK_DATA_SIZE);
    encrypt_data(key, (uint8_t*) data, (uint8_t*) out, sizeof(crypto_block));

    int ret = fwrite(out, sizeof(crypto_block), 1, out_file);

    memcpy(hash, initial_data, 32);

    free(data);
    free(out);
    fclose(out_file);
    
    return (ret == 1) ? 0 : 1;
}

static int read_hash_file(sgx_keydata* key, const char* filename, char* hash) {
    FILE* in_file = fopen(filename, "r");

    if (in_file == NULL) {
        return -1;
    }
    int ret = 0;

    crypto_block* data = calloc(sizeof(crypto_block), 1);
    crypto_block* out = calloc(sizeof(crypto_block), 1);

    fread(data, sizeof(crypto_block), 1, in_file);

    decrypt_data(key, (uint8_t*) data, (uint8_t*) out, sizeof(crypto_block));

    memcpy(hash, out->data, 32);
    if (parity(out->data, BLOCK_DATA_SIZE) != out->parity) {
        ret = -1;
    }

    free(data);
    free(ret);
    fclose(in_file);

    return ret;
}

static int write_hash_file(sgx_keydata* key, const char* filename, char* hash) {
    FILE* out_file = fopen(filename, "w+");
    int ret = 0;

    crypto_block* data = calloc(sizeof(crypto_block), 1);
    crypto_block* out = calloc(sizeof(crypto_block), 1);

    memcpy(data->data, hash, 32);
    data->parity = parity(data->data, BLOCK_DATA_SIZE);

    encrypt_data(key, (uint8_t*) data, (uint8_t*) out, sizeof(crypto_block));

    fwrite(out, sizeof(crypto_block), 1, out_file);

    free(data);
    free(out);
    fclose(out_file);

    return ret;

}

static void append_hash(const char* old, const char* new_sig, char* out) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, old, 32);
    SHA256_Update(&sha256, new_sig, 256);
    SHA256_Final(out, &sha256);
}

static int verify_hash(RSA* key, const char* hash, const char* signed_hash) {
   return 0; 
}

static int sign_data(RSA* key, const char* data, char* sig, size_t len) {
    EVP_PKEY_CTX* ctx;
    EVP_PKEY* sign_key;
    int out = 0;

    sign_key = EVP_PKEY_new();

    out = EVP_PKEY_set1_RSA(sign_key, key);
    if (out != 1) {
        out = -1;
        goto clean;
    }

    ctx = EVP_PKEY_CTX_new(sign_key, NULL);

    if (!ctx) {
        out = -1;
        goto clean;
    }

    size_t siglen;
    char md[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(md, &sha256);

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        out = -1;
        goto clean;
    } else if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        out = -1;
        goto clean;
    } else if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        out = -1;
        goto clean;
    } else if (EVP_PKEY_sign(ctx, NULL, &siglen, md, 32) <= 0) {
        out = -1;
        goto clean;
    } else if (EVP_PKEY_sign(ctx, sig, &siglen, md, 32) <= 0) {
        out = -1;
        goto clean;
    }

clean:
    EVP_PKEY_free(sign_key);
    
    return out;
}

// Aligns the pointer in the key struct, and initializes it with the EGETKEY instruction.
static void sgx_keydata_init(sgx_keydata* ptr) {
    keyrequest_t keyrequest;
    keyrequest.keyname = SEAL_KEY;

    sgx_getkey(&keyrequest, ptr->data);

    print_key(ptr);
}

static int gen_sign_key(sgx_keydata* key, RSA** rsa) {

    int out = 0;
    int bits = 2048;
    unsigned long e = RSA_F4;

    RAND_seed(key->data, KEY_SIZE);

    BIGNUM* bne = BN_new();
    out = BN_set_word(bne, e);
    *rsa = RSA_new();

    if (out != 1) {
        out = -1;
        goto gen_clean;
    }

    RSA_generate_key_ex(*rsa, bits, bne, NULL);    

    if ((*rsa) != NULL) {
        out = 0;
    }

    gen_clean:
    BN_free(bne);
    if (out != 0) {
        RSA_free(*rsa);
    }

    return out;

}

// If rdrand can be controlled, then this might be vulnerable to attack.
// It's unclear as to whether or not the libc rand() call is in userspace or the enclave
// with opensgx.
static inline uint32_t psirand() {
    uint32_t y;
    __asm__ __volatile__ ("rdrand %0" : "=r" (y));
    return y;
}

void enclave_main() {
    sgx_keydata key;

    const char* hash_filename = "hashes.dat";
    const char* read_fifo = "/tmp/notary_input.fifo";
    const char* write_fifo = "/tmp/notary_output.fifo";
    char hash[32];
    RSA* sign_key = NULL;
    int read_fd = 0;
    int write_fd = 0;

    sgx_keydata_init(&key);

    puts("Loaded key");
    // Load keys
    if (gen_sign_key(&key, &sign_key)) {
        puts("Could not load signing key. Exiting...");
        goto cleanup;
    }

    puts("Generated signing key");
    
    // Open fifos for communication with the frontend
    //
    //
    puts("Loading hash file...");
    int rcode = read_hash_file(&key, hash_filename, hash);
    if (rcode != 0) {
        puts("Bad hash file. Regenerating...");
        rcode = gen_hash_file(&key, hash_filename, hash);
        if (rcode != 0) {
            puts("Failed to create new hash file, giving up.");
            sgx_exit(NULL);
        }
    }
    
    puts("Creating FIFO's");
    remove(read_fifo);
    remove(write_fifo);
    int ficode = mkfifo(read_fifo, 0666);
    if (ficode) {
        perror("Error creating node");
        goto cleanup;
    }

    ficode = mkfifo(write_fifo, 0666);
    if (ficode) {
        perror("Error creating node");
        goto cleanup;
    }

    read_fd = open(write_fifo, O_RDONLY);
    write_fd = open(read_fifo, O_WRONLY);

    puts("Serving...");

    int cls = 0;
    while (!cls) {
        uint8_t control = 0;
        uint8_t response = 0;

        ssize_t rd = read(read_fd, &control, 1);

        if (rd != 1) {
            cls = 1;
        }

        switch (control) {
            case CLOSE_NOTARY: {
                response = OK;
                write(write_fd, &response, 1);
                cls = 1;
                               }
                break;

            case SIGN_DATA: {
                uint64_t len = 0;
                response = OK;
                rd = read(read_fd, &len, sizeof(uint64_t));
                if (rd != sizeof(uint64_t)) {
                    cls = 1;
                    break;
                }
                if (len > MAX_FILE_SIZE) {
                    response = TOO_BIG;
                    write(write_fd, &response, 1);
                }
                uint8_t* buf = calloc(len, 1);
                if (!buf) {
                    puts("Could not allocate mem for buffer");
                    response = ERROR;
                    write(write_fd, &response, 1);
                    cls = 1;
                    break;
                }
                size_t len_read = 0;
                while (len_read < len) {
                    rd = read(read_fd, (buf + len_read), len - len_read);
                    if (rd < 0) {
                        perror("Failed to read data");
                        response = ERROR;
                        write(write_fd, &response, 1);
                        free(buf);
                        cls = 1;
                        break;
                    } else {
                        len_read += rd;
                    }
                }
                if (len_read != len) {
                    response = ERROR;
                    write(write_fd, &response, 1);
                    free(buf);
                    cls = 1;
                    break;
                }
                char data_sig[256];
                sign_data(sign_key, buf, data_sig, len);
                free(buf);
                char nhash[32];
                append_hash(hash, data_sig, nhash);
                memcpy(hash, nhash, 32);
                write_hash_file(&key, hash_filename, hash);
                response = SENDING;
                len = 256;
                write(write_fd, &response, 1);
                write(write_fd, &len, sizeof(uint64_t));
                write(write_fd, data_sig, len); 
                            }
                break;

            default:
                {
                puts("Bad input");
                cls = 1;
                break;
                }

        }
    }


cleanup:
    close(read_fd);
    close(write_fd);
    remove(read_fifo);
    remove(write_fifo);
    RSA_free(sign_key);

    sgx_exit(NULL);
}
