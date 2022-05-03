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
#include <sys/socket.h>
#include <arpa/inet.h>

#define LISTENQ 1024
#define PORT 40000

#define BUFFER_SIZE 1024 // Should be larger than Sha digest size we use (cuz we may concatenate some variables)

double tvgetf()
{
    struct timespec ts;
    double sec;

    clock_gettime(CLOCK_REALTIME, &ts);
    sec = ts.tv_nsec;
    sec /= 1e9;
    sec += ts.tv_sec;

    return sec;
}

static int open_listenfd(int port)
{
    int listenfd, optval = 1;

    /* socket */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return -1;
    }
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval, sizeof(int)) < 0) {
    	return -1;
    }

    struct sockaddr_in serveraddr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons((unsigned short) port),
        .sin_zero = {0},
    };
    
    if (bind(listenfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) {
	    perror("bind");
        return -1;
    }

    if (listen(listenfd, LISTENQ) < 0) {
        return -1;
    }

    return listenfd;
}


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

    int listenfd = open_listenfd(PORT);
	/* Authentication Phase */
	struct sockaddr_in clientaddr;
	socklen_t inlen = sizeof(clientaddr);

	int sockfd = accept(listenfd, (struct sockaddr *) &clientaddr, &inlen);
	if (sockfd < 0) {
	    printf("accept error\n");
		return -1;
	} 
	/* Client Sends message 3 to server */
    uint8_t buf[4096] = {};

	uint8_t m1[SHA256_DIGEST_SIZE] = {};
	uint8_t m2[SHA256_DIGEST_SIZE] = {};
	uint8_t f3[SHA256_DIGEST_SIZE] = {};
	uint8_t aid_i[SHA256_DIGEST_SIZE] = {};

	double t1 = tvgetf();
	ret = read(sockfd, buf, sizeof(buf));

	if (ret != SHA256_DIGEST_SIZE*4) {
	    printf("read failed\n");
		return -1;
	}
	memcpy(m1, buf, SHA256_DIGEST_SIZE);
	memcpy(m2, buf+SHA256_DIGEST_SIZE, SHA256_DIGEST_SIZE);
	memcpy(f3, buf+SHA256_DIGEST_SIZE*2, SHA256_DIGEST_SIZE);
	memcpy(aid_i, buf+SHA256_DIGEST_SIZE*3, SHA256_DIGEST_SIZE);

    /* Server regenerate client's identity with m1, m2. f3, aid_i, psk*/
    // f1_bar
    byte f1_bar[SHA256_DIGEST_SIZE] = {};
    for (int i=0; i<SHA256_DIGEST_SIZE; i++) {
        f1_bar[i] = f3[i] ^ psk[i];
    }

    wc_Sha256Update(&sha, f1_bar, sizeof(f1_bar));
    wc_Sha256Final(&sha, hash_tmp); // hash_tmp == f2_bar here
    wc_Sha256Update(&sha, hash_tmp, sizeof(hash_tmp));
    wc_Sha256Final(&sha, hash_tmp); // hash_tmp == hash(f2_bar) here
    
    // r1_bar
    byte r1_bar[SHA256_DIGEST_SIZE] = {};
    for (int i=0; i<SHA256_DIGEST_SIZE; i++) {
        r1_bar[i] = m1[i] ^ hash_tmp[i];
    }
    
    wc_Sha256Update(&sha, r1_bar, sizeof(r1_bar));
    wc_Sha256Final(&sha, hash_tmp); // hash_tmp == hash(r1_bar) here

    // id_bar
    byte id_bar[SHA256_DIGEST_SIZE] = {};
    for (int i=0; i<SHA256_DIGEST_SIZE; i++) {
        id_bar[i] = aid_i[i] ^ hash_tmp[i];
    }

    printf("\nVerify if M2 equals to hash(R1||M2||AID_i)...");
    
    // tmp == (r1_bar||m1||aid_i) here
    memcpy(tmp, r1_bar, sizeof(r1_bar));
    memcpy(tmp + sizeof(r1_bar), m1, sizeof(m1));
    memcpy(tmp + sizeof(r1_bar) + sizeof(m1), aid_i, sizeof(aid_i));

    wc_Sha256Update(&sha, tmp, sizeof(r1_bar) + sizeof(m1) + sizeof(aid_i));
    wc_Sha256Final(&sha, hash_tmp); // hash_tmp == hash(tmp) == hash(r1_bar||m1||aid_i) here
    /*printf("M2   : ");
    for(int i=0; i<SHA256_DIGEST_SIZE; i++) {
        printf("%02x", m2[i]);
    }
    printf("\n");
    printf("Check: ");
    for(int i=0; i<SHA256_DIGEST_SIZE; i++) {
        printf("%02x", hash_tmp[i]);
    }
    printf("\n");*/

    for(int i=0; i<SHA256_DIGEST_SIZE; i++) {
        if(m2[i] != hash_tmp[i]) {
	    printf("Wrong!\n");
	    return -1;
	}
    }
    printf("Pass!\n");
    
    // r2
    byte r2[SHA256_DIGEST_SIZE] = {};
    if (wc_RNG_GenerateBlock(&rng, r2, SHA256_DIGEST_SIZE) != 0) {
        printf("Generate r2 failed\n");
	return -1;
    } else {
        printf("r2 created: ");
	for(int i=0; i< sizeof(r2); i++) {
	    printf("%02x", r2[i]);
	}
	printf("\n");
    }

    // aid_j
    wc_Sha256Update(&sha, id_bar, sizeof(id_bar));
    wc_Sha256Final(&sha, hash_tmp); // hash_tmp == hash(id) here

    byte aid_j[SHA256_DIGEST_SIZE] = {};
    for (int i=0; i<SHA256_DIGEST_SIZE; i++) {
        aid_j[i] = r2[i] ^ hash_tmp[i];
    }

    // m11
    byte m11[SHA256_DIGEST_SIZE] = {};
    for (int i=0; i<SHA256_DIGEST_SIZE; i++) {
        m11[i] = f1_bar[i] ^ hash_tmp[i];
    }

    // m22
    byte m22[SHA256_DIGEST_SIZE] = {};
    memcpy(tmp, m11, sizeof(m11));
    memcpy(tmp + sizeof(m11), aid_j, sizeof(aid_j));
    memcpy(tmp + sizeof(m11) + sizeof(aid_j), r2, sizeof(r2));

    wc_Sha256Update(&sha, tmp, sizeof(m11) + sizeof(aid_j) + sizeof(r2));
    wc_Sha256Final(&sha, m22); // hash_tmp == hash(tmp) == hash(r1_bar||m1||aid_i) here

    // Server create session key
    byte sk1[SHA256_DIGEST_SIZE] = {};
    memcpy(tmp, r1_bar, sizeof(r1_bar));
    memcpy(tmp + sizeof(r1_bar), r2, sizeof(r2)); // tmp == (r1||r2) here

    wc_Sha256Update(&sha, tmp, sizeof(r1_bar) + sizeof(r2));
    wc_Sha256Final(&sha, sk1);
    
    printf("server session key: ");
    for(int i=0; i<SHA256_DIGEST_SIZE; i++) {
        printf("%02x", sk1[i]);
    }
    printf("\n");

    /* Server send message 4 to client  */
    memcpy(buf, m11, SHA256_DIGEST_SIZE);
    memcpy(buf+SHA256_DIGEST_SIZE, m22, SHA256_DIGEST_SIZE);
    memcpy(buf+SHA256_DIGEST_SIZE*2, aid_j, SHA256_DIGEST_SIZE);

	ret = write(sockfd, buf, SHA256_DIGEST_SIZE*3);
	if (ret != SHA256_DIGEST_SIZE*3) {
	    printf("write failed\n");
		return -1;
	}

    /* Client sends message 5 to server*/
    byte m111[SHA256_DIGEST_SIZE] = {};
	ret = read(sockfd, buf, sizeof(buf));
	if (ret != SHA256_DIGEST_SIZE) {
	    printf("read2 may failed\n");
		return -1;
	}
	memcpy(m111, buf, SHA256_DIGEST_SIZE);

    wc_Sha256Update(&sha, r2, sizeof(r2));
    wc_Sha256Final(&sha, hash_tmp); // hash_tmp == hash(r2) here
    // because r2 == r2_bar, thus I reuse hash_tmp here
    printf("\nVerify client's integrity with m111...");
    for (int i=0; i<SHA256_DIGEST_SIZE; i++) {
        if ((m111[i] ^ sk1[i]) != hash_tmp[i]) {
	    printf("Something wrong!\n");
	    return -1;
	}
    }
	double t2 = tvgetf();
    printf("Pass! %f\n", (t2-t1)*1000);

    printf("\nWhole Process Finished successfully, exit!\n");
    /* Free WolfSSL structure */
    wc_Sha256Free(&sha);
    if (wc_FreeRng(&rng) != 0)
        return -1;
    
    return 0;
}
