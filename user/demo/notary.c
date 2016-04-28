#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sgx-lib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define bswap_64bit(x) htobe64(x)
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

typedef struct {
    uint8_t data[KEY_SIZE];
} sgx_keydata __attribute__((aligned(16)));

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

static uint8_t set_block_parity(crypto_block* data) {
    data->parity = parity(data->data, BLOCK_DATA_SIZE);
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

    for (size_t i = 0; i < len; i += KEY_SIZE) {
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
    char hex_representation[KEY_SIZE * 2 + 1] = {'\0'};
    for (int i = 0; i < KEY_SIZE; i++) {
        char byte_hex_rep[16] = {'\0'};
        sprintf(byte_hex_rep, "%02hhX", (unsigned char) ptr->data[i]);
        strcat(hex_representation, byte_hex_rep);
    }

    puts("Key is:");
    puts(hex_representation);

}

static void print_binary(const char* str, int len) {
    char* hex_representation = calloc(2 * len + 1, 1);
    for (int i = 0; i < len; i++) {
        char byte_hex_rep[16] = {'\0'};
        sprintf(byte_hex_rep, "%02hhX", (unsigned char) str[i]);
        strcat(hex_representation, byte_hex_rep);
    }

//    puts("Key is:");
    puts(hex_representation);
    free(hex_representation);

}

static void sprint_key(char* buf, sgx_keydata* ptr) {
    char hex_representation[KEY_SIZE * 2 + 1] = {'\0'};
    for (int i = 0; i < KEY_SIZE; i++) {
        char byte_hex_rep[16] = {'\0'};
        sprintf(byte_hex_rep, "%02hhX", (unsigned char) ptr->data[i]);
        strcat(hex_representation, byte_hex_rep);
    }

    strcpy(buf, hex_representation);

}

typedef struct {
    uint64_t data[32];
} hash_file_t;

//static uint64_t bswap_64bit(uint64_t in) {
//    uint64_t ret;
//    __asm__ volatile ("bswap %0" : "=r" (ret) : "r" (in));
//    return ret;
//}

static int gen_hash_file(sgx_keydata* key, const char* filename, char* hash) {
    FILE* out_file = fopen(filename, "w+");

    crypto_block* data = calloc(sizeof (crypto_block), 1);
    crypto_block* out = calloc(sizeof (crypto_block), 1);

    uint64_t initial_data[] = {
        bswap_64bit(0xdeadbeefcafebabe),
        bswap_64bit(0xcafebabedeadbeef),
        bswap_64bit(0xc001d00dba5eba11),
        bswap_64bit(0xca11ab1edeadbea7)
    };

    memcpy(data->data, initial_data, 32);
    data->parity = parity(data->data, BLOCK_DATA_SIZE);
    encrypt_data(key, (uint8_t*) data, (uint8_t*) out, sizeof (crypto_block));

    int ret = fwrite(out, sizeof (crypto_block), 1, out_file);

    memcpy(hash, initial_data, 32);

    free(data);
    free(out);
    fclose(out_file);

    return (ret == 1) ? 0 : 1;
}

static int read_hash_file(sgx_keydata* key, const char* filename, char* hash) {
    FILE* in_file = fopen(filename, "r");

    puts("reading hash file");

    if (in_file == NULL) {
        return -1;
    }
    int ret = 0;

    crypto_block* data = calloc(sizeof (crypto_block), 1);
    crypto_block* out = calloc(sizeof (crypto_block), 1);

    fread(data, sizeof (crypto_block), 1, in_file);

    puts("Decrypting hash...");

    decrypt_data(key, (uint8_t*) data, (uint8_t*) out, sizeof (crypto_block));

    memcpy(hash, out->data, 32);
    if (parity(out->data, BLOCK_DATA_SIZE) != out->parity) {
        ret = -1;
    }

    puts("Done decrypting.");

    free(data);
    free(out);
    fclose(in_file);

    return ret;
}

static int write_hash_file(sgx_keydata* key, const char* filename, char* hash) {
    FILE* out_file = fopen(filename, "w+");
    int ret = 0;

    crypto_block* data = calloc(sizeof (crypto_block), 1);
    crypto_block* out = calloc(sizeof (crypto_block), 1);

    memcpy(data->data, hash, 32);
    data->parity = parity(data->data, BLOCK_DATA_SIZE);

    encrypt_data(key, (uint8_t*) data, (uint8_t*) out, sizeof (crypto_block));

    fwrite(out, sizeof (crypto_block), 1, out_file);

    free(data);
    free(out);
    fclose(out_file);

    return ret;

}

static void append_hash(const char* old, const char* new_data, size_t len, char* out) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, old, 32);
    SHA256_Update(&sha256, new_data, len);
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

static int gen_sign_key(sgx_keydata* key, RSA** rsa, const char* filename) {

    int out = 0;
    int bits = 2048;
    unsigned long e = RSA_F4;

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

    FILE* key_file = fopen(filename, "w+");
    if (key_file == NULL) {
        out = 1;
        goto gen_clean;
    }

    char keybuf[2 * KEY_SIZE + 1] = "test";
    //    sprint_key(keybuf, key);
    puts(keybuf);

    out = PEM_write_RSAPrivateKey(key_file, *rsa, EVP_bf_cbc(),
            NULL, 0,
            NULL, keybuf);

    if (!out) {
        out = -1;
        goto gen_clean;
    }
    out = 0;

gen_clean:
    fclose(key_file);
    BN_free(bne);
    if (out != 0) {
        RSA_free(*rsa);
    }

    return out;

}

static int key_cb(char* buf, int size, int rwflag, void *u) {
    puts("In callback");
    int len = size < 2 * KEY_SIZE + 1 ? size : 2 * KEY_SIZE + 1;
    memcpy(buf, u, len);
    return len;
}

static int load_sign_key(sgx_keydata* key, RSA** sign_key, const char* filename) {
    int out = 0;
    FILE* key_file = fopen(filename, "r");

    puts("Opened file...");

    if (key_file == NULL) {
        return 1;
    }

    puts("Trying to read key...");

    char keybuf[2 * KEY_SIZE + 1] = "test";
    char errbuf[256] = {0};
    //    sprint_key(keybuf, key);
    puts(keybuf);

    void* success_ptr = PEM_read_RSAPrivateKey(key_file, sign_key, NULL, keybuf);

    if (NULL == *sign_key) {
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
        out = 1;
        puts("Failed to read key.");
        goto load_clean;
    }

load_clean:
    fclose(key_file);

    return out;

}

// If rdrand can be controlled, then this might be vulnerable to attack.
// It's unclear as to whether or not the libc rand() call is in userspace or the enclave
// with opensgx.

static inline uint32_t psirand() {
    uint32_t y;
    __asm__ __volatile__("rdrand %0" : "=r" (y));
    return y;
}

#define CHK_NULL(x) if ((x)==NULL) {puts("Failed!"); return NULL;}
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); return NULL; }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); return NULL; }
#define HOST_RESOURCE "/"
#define HOST_NAME "www.google.com"

int hostname_to_ip(char * hostname , char* ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
         
    if ( (he = gethostbyname( hostname ) ) == NULL) 
    {
        // get the host info
        herror("gethostbyname");
        return 1;
    }
 
    addr_list = (struct in_addr **) he->h_addr_list;
     
    for(i = 0; addr_list[i] != NULL; i++) 
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }
     
    return 1;
}

#define BUF_SIZE 1024 * 64

static char* get_webpage_data(size_t* len) {

    int err;
    int sd;
    int res;
    struct sockaddr_in sa;
    SSL_CTX* ctx;
    SSL* ssl;
    X509* server_cert;
    char* str;
    char ip [128];
    SSL_METHOD *meth;
    const char* request = "GET " HOST_RESOURCE " HTTP/1.1\r\n"
              "Host: " HOST_NAME "\r\n"
              "Connection: close\r\n\r\n";

    OpenSSL_add_ssl_algorithms();
    meth = TLSv1_2_client_method();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(meth);
    CHK_NULL(ctx);
    puts("Loading certs...");
    
//    if (!(1 == SSL_CTX_load_verify_locations(ctx, "cacert.pem", NULL))) {
//        return NULL;
//    }
    
    puts("Connecting...");

    /* ----------------------------------------------- */
    /* Create a socket and connect to server using normal socket calls. */

    sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(sd, "socket");

    memset(&sa, 0, sizeof (sa));
    sa.sin_family = AF_INET;
    hostname_to_ip(HOST_NAME, ip);
    sa.sin_addr.s_addr = inet_addr(ip); /* Server IP */
    sa.sin_port = htons(443); /* Server Port number */

    err = connect(sd, (struct sockaddr*) &sa,
            sizeof (sa));
    CHK_ERR(err, "connect");
    
    puts("Connected.");

    /* ----------------------------------------------- */
    /* Now we have TCP conncetion. Start SSL negotiation. */

    
    
    ssl = SSL_new(ctx);
    CHK_NULL(ssl);
    puts("Performing handshake...");
    SSL_set_fd(ssl, sd);
    err = SSL_connect(ssl);
    CHK_SSL(err);

    /* Following two steps are optional and not required for
       data exchange to be successful. */

    /* Get the cipher - opt */

    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    /* Get server's certificate (note: beware of dynamic allocation) - opt */

    server_cert = SSL_get_peer_certificate(ssl);
    CHK_NULL(server_cert);
    printf("Server certificate:\n");

    str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t subject: %s\n", str);
    OPENSSL_free(str);

    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t issuer: %s\n", str);
    OPENSSL_free(str);

    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */
    
    // Getting proper time for verification may be an issue.
//    res = SSL_get_verify_result(ssl);
//    if (res != X509_V_OK) {
//        puts("Bad cert?");
//        print_binary(&res, sizeof(int));
//        return NULL;
//    }
    
    X509_free(server_cert);
    
    

    /* --------------------------------------------------- */
    /* DATA EXCHANGE - Send a message and receive a reply. */
    puts("Sending data...");
    err = SSL_write(ssl, request, strlen(request));
    CHK_SSL(err);

    puts("Receiving response...");
    char* buf = calloc(BUF_SIZE, 1);
    size_t read = 0;
    
    do {
        err = SSL_read(ssl, buf, read + (BUF_SIZE - 1));
        CHK_SSL(err);
        read += err;
    } while (read < BUF_SIZE-1 && err > 0);
    
    
    
    
    buf[err] = '\0';
    printf("Got %d chars:\n", read);
    print_binary(buf, 64);
    SSL_shutdown(ssl); /* send SSL/TLS close_notify */

    /* Clean up. */

    close(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    
    *len = read;
    return buf;



}

void enclave_main() {
    sgx_keydata key;

    const char* hash_filename = "hashes.dat";
    const char* key_file = "key.pem";
    char hash[32];
    RSA* sign_key = NULL;
    int read_fd = 0;
    int write_fd = 0;
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    sgx_keydata_init(&key);

    puts("Loaded key");
    // Load keys
    if (load_sign_key(&key, &sign_key, key_file)) {
        puts("Failed to load signing key... regenerating.");
        if (gen_sign_key(&key, &sign_key, key_file)) {
            puts("Could not load signing key. Exiting...");
            goto cleanup;
        }
        //        goto cleanup;
    }

    puts("Loaded signing key");

    puts("Loading hash file...");
    int rcode = read_hash_file(&key, hash_filename, hash);
    puts("Tried loading hash file...");
    if (rcode != 0) {
        puts("Bad hash file. Regenerating...");
        rcode = gen_hash_file(&key, hash_filename, hash);
        if (rcode != 0) {
            puts("Failed to create new hash file, giving up.");
            sgx_exit(NULL);
        }
    }
    puts("Succeeded.");
    puts("Old hash: ");
    print_binary(hash, 32);
    size_t data_len = 0;

    // Establish secure connection with website, download site
    char* data = get_webpage_data(&data);
    if (data == NULL) {
        puts("Failed to connect.");
        goto cleanup;
    }
    

    // Compute hash, 
    char new_hash[32];
    append_hash(hash, data, data_len, new_hash);
    
    write_hash_file(&key, hash_filename, new_hash);
    puts("New hash:");
    
    print_binary(new_hash, 32);

    
cleanup:
    fflush(stdout);
    free(data);
    RSA_free(sign_key);
    EVP_cleanup();
    puts("Exiting.");

    sgx_exit(NULL);
}
