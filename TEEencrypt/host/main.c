#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;	
	int len = 64;	
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char encrypt_text[64] = {0,};
	char encrypt_key[64] = {0,};

	char clear[RSA_MAX_PLAIN_LEN_1024];
	char ciph[RSA_CIPHER_LEN_1024];
	
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	//Run Ceaser
	if (!strcmp(argv[2], "Ceaser")){
		//Run Encryption
		if (!strcmp(argv[1], "-e")){
			printf("========================Encryption========================\n");
			//File Read and Get plaintext
			FILE *fp = fopen(argv[3], "r");
			fgets(plaintext, sizeof(plaintext), fp);
			fclose(fp);
			
			//op.params.Buffer copy plaintext
			memcpy(op.params[0].tmpref.buffer, plaintext, len); 
			
			//Invoke TA_TEEencrypt_CMD_ENC_VALUE
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);

			//ciphertext copy op.params.Buffer
			memcpy(ciphertext, op.params[0].tmpref.buffer, len);

			printf("Encrypt text : %s\n", ciphertext);
			printf("key : %d\n", op.params[1].value.a);
			
			//File open and save ciphertext
			FILE *fp2 = fopen("encrypt_text.txt", "w+");
			fwrite(ciphertext, strlen(ciphertext), 1, fp2);
			fclose(fp2);

			//File open and save encrpyed key 
			FILE *fp3 = fopen("encrypt_key.txt", "w+");
			fprintf(fp3, "%d", op.params[1].value.a);
			fclose(fp3);
		}
		//Run Decryption
		else if (!strcmp(argv[1], "-d")){
			printf("========================Decryption========================\n");
			//File read and Get Encrypt_text
			FILE *fp = fopen(argv[3], "r");
			fgets(encrypt_text, sizeof(encrypt_text), fp);
			fflush(fp);
			
			//File read and Get Encrypt_key
			fp = fopen(argv[4], "r");
			fgets(encrypt_key, sizeof(encrypt_key), fp);
			fclose(fp);

			//op.params.Buffer copy encrypt_text
			memcpy(op.params[0].tmpref.buffer, encrypt_text, len);

			//save Encrypt_key
			int encrypt_random_key = atoi(encrypt_key);	
			op.params[1].value.a = encrypt_random_key;	
			
			//Invoke TA_TEEencrypt_CMD_DEC_VALUE
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);

			//ciphertext copy op.params.Buffer			
			memcpy(ciphertext, op.params[0].tmpref.buffer, len);
			printf("Decrypt text : %s\n", ciphertext);

			//File open and save ciphertext(decrypt_text)
			FILE *fp2 = fopen("decrypt_file.txt", "w+");
			fwrite(ciphertext, strlen(ciphertext), 1, fp2);
			fclose(fp2);
			
		 }
	}
	//Run RSA
	else if (!strcmp(argv[2], "RSA")){
	
		//Settion op.parameters
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 		TEEC_MEMREF_TEMP_OUTPUT,
					 		TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = clear;
		op.params[0].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
		op.params[1].tmpref.buffer = ciph;
		op.params[1].tmpref.size = RSA_CIPHER_LEN_1024;

		//Run Encryption	
		if (!strcmp(argv[1], "-e")){

			printf("========================Encryption========================\n");
			
			//File read and Get Plaintext
			FILE *fp = fopen(argv[3], "r");
			fgets(plaintext, sizeof(plaintext), fp);
			fclose(fp);
		
			//Invoke RSA_GENKEYS and RSA_ENC 
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_GENKEYS, &op, &err_origin);
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_ENC, &op, &err_origin);

			//ciph copy op.params.Buffer			
			memcpy(ciph, op.params[1].tmpref.buffer, len);
			printf("RSA Encrypt : %s\n", ciph);
			
			//File open and save ciph(Encrypt_text)
			FILE *rfp = fopen("rsa_enc.txt", "w+");
			fwrite(ciph, strlen(ciph), 1, rfp);
			fclose(rfp);
		}
	}
	
	else {
		printf("No such option");
	}


	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
