/* This script reproduces the authentication seheme in the "A Lightweight Authentication Mechanism for M2M Communications in Industrial IoT Environment" article
 * The article defines three characters which are smart sensor, authentication server, and router.
 * There're some differences like the bit length of parameters, character naming
 *
 * Moreover, I implemented the process with WolfSSL library in order to improve the performance.
 */

#include <stdio.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdint.h>
#include <error.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024 // Should be larger than Sha digest size we use (cuz we may concatenate some variables)
#define HOST "127.0.0.1"
#define PORT 40000
int main()
{
    /* WolfSSL structure */
    Sha256 sha;
    RNG rng;

    /* Registration Phase */
    byte tmp[BUFFER_SIZE] = {};
    byte hash_tmp[SHA256_DIGEST_SIZE] = {};

    int ret = wc_InitSha256(&sha);
    if (ret != 0) {
        printf("Sha256 init fail\n");
	return -1;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("RNG init fail\n");
	return -1;
    }

    // Client create ID
    byte id[SHA256_DIGEST_SIZE] = {};
    if (wc_RNG_GenerateBlock(&rng, id, SHA256_DIGEST_SIZE) != 0) {
        printf("Generate random number failed\n");
	return -1;
    } else {
        printf("id created: ");
	for(int i=0; i< sizeof(id); i++) {
	    printf("%02x", id[i]);
	}
	printf("\n");
    }

    // Authentication Server (AS) calculates f1, f2, f3
	int sockfd;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
	    printf("failed to create sock\n");
		return -1;
	}
	struct sockaddr_in info;
	bzero(&info, sizeof(info));
	info.sin_family = PF_INET;
	info.sin_addr.s_addr = inet_addr(HOST);
	info.sin_port = htons(PORT);

	ret = connect(sockfd, (struct sockaddr *)&info, sizeof(info));
	if (ret == -1) {
	    perror("Connection error\n");
		return -1;
	}
    byte x[SHA256_DIGEST_SIZE] = {};
    if (wc_RNG_GenerateBlock(&rng, x, SHA256_DIGEST_SIZE) != 0) {
        printf("Generate x failed\n");
	return -1;
    } else {
        printf("x created: ");
	for(int i=0; i< sizeof(x); i++) {
	    printf("%02x", x[i]);
	}
	printf("\n");
    }

    // tmp == (id||x) here
    memcpy(tmp, id, sizeof(id));
    memcpy(tmp+sizeof(id), x, sizeof(x));
    
    // f1
    byte hash_f1[SHA256_DIGEST_SIZE] = {};
    wc_Sha256Update(&sha, tmp, sizeof(id) + sizeof(x));
    wc_Sha256Final(&sha, hash_f1);
    
    // f2
    byte hash_f2[SHA256_DIGEST_SIZE] = {};
    wc_Sha256Update(&sha, hash_f1, sizeof(hash_f1));
    wc_Sha256Final(&sha, hash_f2);

    // PSK
    byte psk[SHA256_DIGEST_SIZE] = {};
	for (int i=0; i<SHA256_DIGEST_SIZE; i++) {
	    psk[i] = 255;
	}
    /*if (wc_RNG_GenerateBlock(&rng, psk, SHA256_DIGEST_SIZE) != 0) {
        printf("Generate psk failed\n");
	return -1;
    } else {
        printf("psk created: ");
	for(int i=0; i<sizeof(psk); i++) {
	    printf("%02x", psk[i]);
	}
	printf("\n");
    }*/

    byte f3[SHA256_DIGEST_SIZE] = {};
    for(int i=0; i<SHA256_DIGEST_SIZE; i++) {
        f3[i] = psk[i] ^ hash_f1[i];
    }


    /* Authentication Phase */
    byte r1[SHA256_DIGEST_SIZE] = {};
    if (wc_RNG_GenerateBlock(&rng, r1, SHA256_DIGEST_SIZE) != 0) {
        printf("Generate r1 failed\n");
	return -1;
    } else {
        printf("r1 created: ");
	for(int i=0; i< sizeof(r1); i++) {
	    printf("%02x", r1[i]);
	}
	printf("\n");
    }
    
    wc_Sha256Update(&sha, hash_f2, sizeof(hash_f2));
    wc_Sha256Final(&sha, hash_tmp); // hash_tmp == hash(f2) here

    // m1
    byte m1[SHA256_DIGEST_SIZE] = {};
    for(int i=0; i<SHA256_DIGEST_SIZE; i++) {
        m1[i] = hash_tmp[i] ^ r1[i];
    }

    // aid_i
    wc_Sha256Update(&sha, r1, sizeof(r1));
    wc_Sha256Final(&sha, hash_tmp); // hash_tmp == hash(r1) here
    byte aid_i[SHA256_DIGEST_SIZE] = {};
    for (int i=0; i<SHA256_DIGEST_SIZE; i++) {
        aid_i[i] = hash_tmp[i] ^ id[i];
    }

    // m2
    byte m2[SHA256_DIGEST_SIZE] = {};

    // tmp == (r1||m1||aid_i) here
    memcpy(tmp, r1, sizeof(r1));
    memcpy(tmp + sizeof(r1), m1, sizeof(m1));
    memcpy(tmp + sizeof(r1) + sizeof(m1), aid_i, sizeof(aid_i));
    
    wc_Sha256Update(&sha, tmp, sizeof(r1) + sizeof(m1) + sizeof(aid_i));
    wc_Sha256Final(&sha, m2);

    /* Client Sends message 3 to server */
	uint8_t buf [4096] = {};
	memcpy(buf, m1, sizeof(m1));
	memcpy(buf+sizeof(m1), m2, sizeof(m2));
	memcpy(buf+sizeof(m1)+sizeof(m2), f3, sizeof(f3));
	memcpy(buf+sizeof(m1)+sizeof(m2)+sizeof(f3), aid_i, sizeof(aid_i));

	if (write(sockfd, buf, SHA256_DIGEST_SIZE*4) == -1) {
	    printf("write failed\n");
		return -1;
	}
    /* Server send message 4 to client  */
	ret = read(sockfd, buf, sizeof(buf));
	if (ret != SHA256_DIGEST_SIZE*3) {
	    printf("read failed\n");
		return -1;
	}
	uint8_t m11[SHA256_DIGEST_SIZE] = {};
	uint8_t m22[SHA256_DIGEST_SIZE] = {};
	uint8_t aid_j[SHA256_DIGEST_SIZE] = {};

	memcpy(m11, buf, SHA256_DIGEST_SIZE);
	memcpy(m22, buf+SHA256_DIGEST_SIZE, SHA256_DIGEST_SIZE);
	memcpy(aid_j, buf+SHA256_DIGEST_SIZE*2, SHA256_DIGEST_SIZE);

    byte r2_bar[SHA256_DIGEST_SIZE] = {};

    wc_Sha256Update(&sha, id, sizeof(id));
    wc_Sha256Final(&sha, hash_tmp); // hash_tmp == hash(id) here

    for (int i=0; i<SHA256_DIGEST_SIZE; i++) {
        r2_bar[i] = aid_j[i] ^ hash_tmp[i];
    }
    
    for(int i=0; i<SHA256_DIGEST_SIZE; i++) {
        printf("%02x", r2_bar[i]);
    }
    printf("\n");

    memcpy(tmp, m11, sizeof(m11));
    memcpy(tmp + sizeof(m11), aid_j, sizeof(aid_j));
    memcpy(tmp + sizeof(aid_j) + sizeof(m11), r2_bar, sizeof(r2_bar)); // tmp == (r2_bar||m11||aid_j) here

    wc_Sha256Update(&sha, tmp, sizeof(r2_bar) + sizeof(m11) + sizeof(aid_j));
    wc_Sha256Final(&sha, hash_tmp); // hash_tmp == hash(tmp) == hash(r2_bar||m11|aid_j) here

    printf("\nVerify if m22 equals to hash(R2||m11||AID_j)...");
    for(int i=0; i<SHA256_DIGEST_SIZE; i++) {
        if (hash_tmp[i] != m22[i]) {
	    printf("wrong!\n");
	    return -1;
	}
    }
    printf("Pass!\n");

    // client create session key sk2
    byte sk2[SHA256_DIGEST_SIZE] = {};
    memcpy(tmp, r1, sizeof(r1));
    memcpy(tmp + sizeof(r1), r2_bar, sizeof(r2_bar)); // tmp == (r1||r2_bar) here
    wc_Sha256Update(&sha, tmp, sizeof(r1) + sizeof(r2_bar));
    wc_Sha256Final(&sha, sk2);

    printf("Client session key: ");
    for(int i=0; i<SHA256_DIGEST_SIZE; i++) {
        printf("%02x", sk2[i]);
    }
    printf("\n");

    byte m111[SHA256_DIGEST_SIZE] = {};
    wc_Sha256Update(&sha, r2_bar, sizeof(r2_bar));
    wc_Sha256Final(&sha, hash_tmp); // hash_tmp == hash(r2_bar) here

    for (int i=0; i<SHA256_DIGEST_SIZE; i++) {
        m111[i] = sk2[i] ^ hash_tmp[i];
    }

    /* Client sends message 5 to server*/
	if (write(sockfd, m111, SHA256_DIGEST_SIZE) == -1) {
	    printf("write may failed\n");
		return -1;
	}
    printf("\nThe Client Process Finished successfully, exit!\n");
    /* Free WolfSSL structure */
    wc_Sha256Free(&sha);
    if (wc_FreeRng(&rng) != 0)
        return -1;
    
    return 0;
}
