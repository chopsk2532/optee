/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <TEEencrypt_ta.h>
#include <stdio.h>
#include <string.h>

#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)


int root_key;

struct rsa_session {
	TEE_OperationHandle op_handle;	/* RSA operation */
	TEE_ObjectHandle key_handle; /* Key handle */
};

TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key) {
	TEE_Result ret = TEE_SUCCESS;	
	TEE_ObjectInfo key_info;
	ret = TEE_GetObjectInfo1(key, &key_info);
	if (ret != TEE_SUCCESS) {
		EMSG("\nTEE_GetObjectInfo1: %#\n" PRIx32, ret);
		return ret;
	}

	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc operation handle : 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Operation allocated successfully. ==========\n");

	ret = TEE_SetOperationKey(*handle, key);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to set key : 0x%x\n", ret);
		return ret;
	}
    DMSG("\n========== Operation key already set. ==========\n");

	return ret;
}

TEE_Result check_params(uint32_t param_types) {
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}

TEE_Result RSA_create_key_pair(void *session) {
	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session *sess = (struct rsa_session *)session;
	
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Transient object allocated. ==========\n");

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		EMSG("\nGenerate key failure: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Keys generated. ==========\n");
	return ret;
}

TEE_Result RSA_encrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;

	DMSG("\n========== Preparing encryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to encrypt: %s\n", (char *) plain_txt);
	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
					plain_txt, plain_len, cipher, &cipher_len);					
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to encrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nEncrypted data: %s\n", (char *) cipher);
	DMSG("\n========== Encryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeOperation(sess->key_handle);
	return ret;
}

TEE_Result RSA_decrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void *plain_txt = params[1].memref.buffer;
	size_t plain_len = params[1].memref.size;
	void *cipher = params[0].memref.buffer;
	size_t cipher_len = params[0].memref.size;

	DMSG("\n========== Preparing decryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_DECRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to decrypt: %s\n", (char *) cipher);
	ret = TEE_AsymmetricDecrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
				cipher, cipher_len, plain_txt, &plain_len);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to decrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nDecrypted data: %s\n", (char *) plain_txt);
	DMSG("\n========== Decryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeTransientObject(sess->key_handle);
	return ret;
}


TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}


TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
					TEE_Param __unused params[4],
					void __unused **session) {
	struct rsa_session *sess;
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*session = (void *)sess;
	DMSG("\nSession %p: newly allocated\n", *session);

	return TEE_SUCCESS;
}


void TA_CloseSessionEntryPoint(void *session)
{
	struct rsa_session *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: release session", session);
	sess = (struct rsa_session *)session;

	/* Release the session resources
	   These tests are mandatories to avoid PANIC TA (TEE_HANDLE_NULL) */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);
}

static TEE_Result enc_value(uint32_t param_types,
	TEE_Param params[4])
{		
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char encrypted[64]={0,};

	//Generate RANDOM KEY
	unsigned int random_key;
	TEE_GenerateRandom(&random_key, sizeof(random_key));
	random_key = random_key % 26;

	//if Random_key == 0 , not Encryption
	while (random_key == 0){
		TEE_GenerateRandom(&random_key, sizeof(random_key));		
		random_key = random_key % 26;
	}

	DMSG("========================Encryption========================\n");
	DMSG("Plaintext :  %s", in);

	memcpy(encrypted, in, in_len);

	//Encryption text
	for(int i=0; i<in_len; i++){
	 if(encrypted[i] >= 'a' && encrypted[i] <= 'z'){
         	encrypted[i] -= 'a';
         	encrypted[i] += random_key;
         	encrypted[i] = encrypted[i] % 26;
         	encrypted[i] += 'a';
    	 }
      	 else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
         	encrypted[i] -= 'A';
         	encrypted[i] += random_key;
         	encrypted[i] = encrypted[i] % 26;
         	encrypted[i] += 'A';
      	 }
	}
	
	//Encryption Key
	int enc_random_key = random_key + root_key;

	DMSG("encrypted : %s", encrypted);	
	DMSG("enc key : %d", enc_random_key);

	//Save Encryption text and key
	params[1].value.a = enc_random_key;
	memcpy(in, encrypted, in_len);

	
	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{

	//Loading params
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen(params[0].memref.buffer);		
	int in_key = params[1].value.a;
	char decrypted[64] = {0,};

	DMSG("decrypt key : %d", in_key);
	DMSG("decrypt key : %d", root_key);
	//Decryption Key
	int decrypt_key = in_key - root_key;

	DMSG("========================Decryption========================\n");
	DMSG("Encrypted :  %s", in);
	DMSG("decrypt key : %d", decrypt_key);

	memcpy(decrypted, in, in_len);

	//Decryption text
	for(int i=0; i<in_len;i++){
      	 if(decrypted[i]>='a' && decrypted[i] <='z'){
        	decrypted[i] -= 'a';
         	decrypted[i] -= decrypt_key;
         	decrypted[i] += 26;
         	decrypted[i] = decrypted[i] % 26;
         	decrypted[i] += 'a';
      	  }
      	 else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
         	decrypted[i] -= 'A';
         	decrypted[i] -= decrypt_key;
        	decrypted[i] += 26;
         	decrypted[i] = decrypted[i] % 26;
         	decrypted[i] += 'A';
      	  }
         }

	//Save Decryption Text
	DMSG("decrypted : %s", decrypted);
	memcpy(in, decrypted, in_len);

	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */
	root_key = 7;

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_TEEencrypt_CMD_RSA_GENKEYS:
		return RSA_create_key_pair(sess_ctx);
	case TA_TEEencrypt_CMD_RSA_ENC:
		return RSA_encrypt(sess_ctx, param_types, params);
	case TA_TEEencrypt_CMD_RSA_DEC:
		return RSA_decrypt(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
