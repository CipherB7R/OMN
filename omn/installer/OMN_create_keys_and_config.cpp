/**
 * 	This is to be executed locally to the MASTER'S PC.
 * 	It is meant to generate the first two keypairs: MASTER's and SLAVE's. Normally you'll have to deal with it only 1 time, to initialize OMN infrastructure with just ONE MASTER!
 * 	If you want to subsequentially add more "masters" to the SLAVE's keyring, use the appropriate files: "OMN_MASTER_generate_another_keypair.cpp" "OMN_SLAVE_import_another_master_keypair.cpp"
 *
 */
#include "../OMN_common.h"



int main(int argc, char** argv){

	//(possible) error variables. Need them cause it's the way to check if a decryption or verification action fails (bad signature, bad message etc.).
	gpgme_error_t error; //will contain err_code and err_source. We will extract only err_code
	gpgme_err_code_t error_code; //will contain error code of "error" variable. Taken with gpgme_err_code(gpgme_error_t err).


	//first things first! Let's initialize gpgme!
	init_gpgme();
	
	//key management variables.	
	gpgme_key_t public_key_OMN_slave_group;
	gpgme_key_t secret_key_OMN_slave_group;
	//////////////////////////////////
	gpgme_key_t public_key_OMN_master;
	gpgme_key_t secret_key_OMN_master;
	
	//context management variables.
	gpgme_ctx_t encrypt_ctx;

	//create a new context
	if(gpgme_new(&encrypt_ctx) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create a new context\n");
		exit(-1);
	}
	
	//set the OpenPGP protocol for the created context
	if(gpgme_set_protocol(encrypt_ctx, GPGME_PROTOCOL_OpenPGP) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to set openPGP protocol in new context\n");
		exit(-1);
	}

	//Let's use ascii Armor too (radix64 algorythm to produce Base64 output). This way we can send messages over protocols that are designed to carry only text content (like SMTP, a so-called "Byte unsafe" protocol).
	//What if packets are sent via some old network which is not Byte-clean?
	//Yeah, it's a stupid and very unlikely scenario, but since we have the armored option, why not use it for backwards-compatibility?
	//
	//base 64 encoding works like this:
	//
	//take binary data, in groups of 24 bits;
	//
	//divide 'em in groups of 6 bits and use those 6 bits as an index in the 6 bits -> 8-bits PRINTABLE char conversion table; (Here comes the 33% overhead!)
	//
	//now you have 24/6 -> 4 chars (4*8 = 32 bits) representing 24/8 -> 3 bytes of data.
	//
	//
	//
	//THIS GROUPING IS BEEN CHOSEN BECAUSE OF SIMPLICITY IN PADDING WITH (normally) "=" char -----> Only 3 cases:
	//
	//Last group of 24 bits is only long 2 bytes (16 bits) -> 3 non-null chars (till 6*3 = 18 bits, last 18-16=2 bits are just discarded when decoded!) + 1 char "=" of padding
	//
	//Last group of 24 bits is only long 1 byte (8 bits) -> 2 non-null-chars + 2 chars "=" of padding
	//
	//Last group of 24 bits is 3 bytes long -> All ok 3*8 = 24 bits -> 4 non-null chars
	gpgme_set_armor(encrypt_ctx, 1);

	
	/**************************************************************************************************************************************************************************/
	//FIRST OFF, THE PUB/SEC KEYPAIR FOR THE SLAVES, THE SAME FOR EACH ONE OF THEM!
	/**************************************************************************************************************************************************************************/
	
	fprintf(stdout, "Creating slave group gpg keys\n");
	fprintf(stdout, "Press enter to continue...\n");
	getchar();
	//let's generate an RSA public key keypair, with userid "OMN slave group key", reasonable expire time (0, page 63 gpgme manual),   
	//and set it so we can only encrypt and decrypt with it.
	if(gpgme_op_createkey(encrypt_ctx, "OMN group slave", "rsa", 0, 0, NULL, GPGME_CREATE_ENCR | GPGME_CREATE_NOPASSWD) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create createkey job for slaves' group keys\n");
		exit(-1);
	}

	//let's retrieve the generated key.
	gpgme_genkey_result_t temp_genkey_result = gpgme_op_genkey_result(encrypt_ctx);
	
	if(temp_genkey_result == NULL) {	
		fprintf(stderr, "Failed to retrieve createkey result\n");
		exit(-1);
	} else {
		if(temp_genkey_result->primary != 1) {
			
			fprintf(stderr, "Created key is not primary\n");
			//should we delete it?
			exit(-1);
		}

		fprintf(stdout, "Here is the fingerprint of the created key: %s\n", temp_genkey_result->fpr);
	}


	
	fprintf(stdout, "Let's try to retrieve 'em from the keychain, to create master's config file later.\nNOTE: when gpgme creates a key, it is automatically added to GPG keychain as a trusted key!\n");


	//now let's get the key, secret = 0 so we take only the PUBLIC key.	
	if(gpgme_get_key(encrypt_ctx, temp_genkey_result->fpr, &public_key_OMN_slave_group, 0) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to retrieve createkey result (public key!)\n");
		exit(-1);
	} else {
		if(public_key_OMN_slave_group == NULL) {
			
			fprintf(stderr, "FAILED TO RETRIEVE PUBLIC KEY FOR OMN SLAVE\n");
			//should we delete it?
			exit(-1);
		}

	}

	//let's get the secret key too...
	if(gpgme_get_key(encrypt_ctx, temp_genkey_result->fpr, &secret_key_OMN_slave_group, 1) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to retrieve createkey result (secret key)\n");
		exit(-1);
	} else {
		if(secret_key_OMN_slave_group == NULL) {
			
			fprintf(stderr, "FAILED TO RETRIEVE SECRET KEY FOR OMN SLAVE\n");
			//should we delete it?
			exit(-1);
		}

	}

	fprintf(stdout, "Slave group key retrieved! Fingerprint %s --- Is secret? %d\n", public_key_OMN_slave_group->fpr, public_key_OMN_slave_group->secret);
	fprintf(stdout, "Slave group key retrieved! Fingerprint %s --- Is secret? %d\n", secret_key_OMN_slave_group->fpr, secret_key_OMN_slave_group->secret);



	/**************************************************************************************************************************************************************************/
	//SECOND, THE PUB/SEC KEYPAIR FOR THE MASTER!
	/**************************************************************************************************************************************************************************/

	fprintf(stdout, "Give me a lan name (max 127 characters) for the master... ");
	char lan_name[128] = "";
	scanf("%127s", lan_name);
	
	fprintf(stdout, "Generating NORM id... MAKE SURE YOU ACCEPT A NUMBER THAT YOU HAVE NEVER SEEN BEFORE!\n");
	
	fprintf(stdout, "Press enter to continue...\n");
	getchar();

	NormNodeId generated_NORMID = generate_local_id();
	fprintf(stdout, "Generated NORM id %u. ", generated_NORMID);
	while(!yes_or_no_choice("Keep it?")) {
		generated_NORMID = generate_local_id();
		fprintf(stdout, "Generated NORM id %u. ", generated_NORMID);
	}

	fprintf(stdout, "Creating master's PGP keys, YOU MUST ENTER A PASSWORD TO PROTECT THIS KEYPAIR!\n");

	fprintf(stdout, "Press enter to continue...\n");
	getchar();
	
	//let's generate an RSA public key keypair, with userid "OMN master " + LAN_NAME + NORMid , reasonable expire time (0, page 63 gpgme manual),   
	std::string uid = std::string("OMN master ") + std::string(lan_name) + std::string(" ") + std::to_string(generated_NORMID);
	if(gpgme_op_createkey(encrypt_ctx, uid.c_str(), "rsa", 0, 0, NULL, GPGME_CREATE_SIGN | GPGME_CREATE_AUTH | GPGME_CREATE_ENCR) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create createkey job for master's keys\n");
		exit(-1);
	}

	//let's retrieve the generated key.
	temp_genkey_result = gpgme_op_genkey_result(encrypt_ctx);
	
	if(temp_genkey_result == NULL) {	
		fprintf(stderr, "Failed to retrieve createkey result\n");
		exit(-1);
	} else {
		if(temp_genkey_result->primary != 1) {
			
			fprintf(stderr, "Created key is not primary\n");
			//should we delete it?
			exit(-1);
		}

		fprintf(stdout, "Here is the fingerprint of the created key: %s\n", temp_genkey_result->fpr);
	}


	
	fprintf(stdout, "Let's try to retrieve 'em from the keychain, to create master's config file later.\nNOTE: when gpgme creates a key, it is automatically added to GPG keychain!\n");


	//now let's get the key, secret = 0 so we take only the PUBLIC key.	
	if(gpgme_get_key(encrypt_ctx, temp_genkey_result->fpr, &public_key_OMN_master, 0) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to retrieve createkey result (public key!)\n");
		exit(-1);
	} else {
		if(public_key_OMN_master == NULL) {
			
			fprintf(stderr, "FAILED TO RETRIEVE PUBLIC KEY FOR OMN MASTER\n");
			//should we delete it?
			exit(-1);
		}

	}

	//let's get the secret key too...
	if(gpgme_get_key(encrypt_ctx, temp_genkey_result->fpr, &secret_key_OMN_master, 1) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to retrieve createkey result (secret key)\n");
		exit(-1);
	} else {
		if(secret_key_OMN_master == NULL) {
			
			fprintf(stderr, "FAILED TO RETRIEVE SECRET KEY FOR OMN MASTER\n");
			//should we delete it?
			exit(-1);
		}

	}

	fprintf(stdout, "Master key retrieved! Fingerprint %s --- Is secret? %d\n", public_key_OMN_master->fpr, public_key_OMN_master->secret);
	fprintf(stdout, "Master key retrieved! Fingerprint %s --- Is secret? %d\n", secret_key_OMN_master->fpr, secret_key_OMN_master->secret);


	/**************************************************************************************************************************************************************************/
	//THID, Let's EXPORT THEM (and create cfg file for master only)!
	/**************************************************************************************************************************************************************************/

	//Let's export them, in order to save 'em in a file to be imported in a new PC!
	//first off, let's create a NULL-terminated array containing the public and secret OMN slave keys.
	gpgme_data_t keys_to_be_exported;
		
	
	/**************************************************************************************************************************************************************************/
	/********************************** we don't need both public and secret keys, only secret one thanks to "GPGME_EXPORT_MODE_SECRET" ***************************************/
	//gpgme_key_t v_exporting_keys[3] = {public_key_OMN_slave, secret_key_OMN_slave, NULL};
	/**************************************************************************************************************************************************************************/
	
	gpgme_key_t v_exporting_seckeys[2] = {secret_key_OMN_slave_group, NULL};
	gpgme_key_t v_exporting_pubkeys[2] = {public_key_OMN_master, NULL};

	//let's initialize the data buffer.
	//we need a gpgme_data_t object... let's create it with gpgme_data_new... this function will return its handle inside the variable cleartext.
	if(gpgme_data_new(&keys_to_be_exported) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object!\n");
		exit(-1);
	}

	//we need just the secret key to be exported, cause it contains the public key too...
	if(gpgme_op_export_keys(encrypt_ctx, v_exporting_seckeys, GPGME_EXPORT_MODE_SECRET, keys_to_be_exported) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to export slave's keypair\n");
		exit(-1);
	}

	//now the public key (only it!) for the master.
	if(gpgme_op_export_keys(encrypt_ctx, v_exporting_pubkeys, 0, keys_to_be_exported) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to export master's pubkey\n");
		exit(-1);
	}

	//...and let's store it into a file.
	size_t length_of_keys_data;
	char* data_tmp = gpgme_data_release_and_get_mem(keys_to_be_exported, &length_of_keys_data);
	
	if(data_tmp == NULL) {
		fprintf(stderr, "Failed to release and get export memory\n");
	} else {
		//let's store it into a file!
		FILE* fp = fopen("exported_keys_for_OMNslave.txt", "wb");
		if(fp == NULL) fprintf(stderr, "Failed to open file!\n");
		else {

			fwrite(data_tmp, sizeof(char), length_of_keys_data, fp);
			fprintf(stdout, "Successfully printed all key data inside file exported_keys_for_OMNslave.txt!\n");
			fclose(fp);
		}
	}

	//let's create the config file, used by OMN (master's and slave's) as a dictionary of fingerprints he needs to use for crypto operations.
	std::string omn_filepath = std::string(getenv("HOME")) + "/" + std::string(OMN_DIRECTORY);

	struct stat st = {0};
	if(stat(omn_filepath.c_str(), &st) == -1) {
		mkdir(omn_filepath.c_str(), 0775);
	}

	std::string complete_filepath = omn_filepath + "/" + std::string(OMN_CFG_FILENAME);
	FILE* fp = fopen(complete_filepath.c_str(), "w");
	if(fp == NULL) fprintf(stderr, "Failed to open file!\n");
	else {
		

		fprintf(fp, "master:%s\nslave_group:%s\nlan_name:%s\nNORM_ID:%u\n", public_key_OMN_master->fpr, public_key_OMN_slave_group->fpr, lan_name, generated_NORMID);
		fprintf(stdout, "Successfully created OMN config file %s\n", complete_filepath.c_str());
		fclose(fp);
	}

	fprintf(stdout, "What's next you may ask...\nNow you need to pick up the exported key keyfile and import it everywhere you want to install OMN as a slave!\nDuring the installation it will be considered and used.\n");

	//we need to free the data buffer we got with gpgme_data_release_and_get_mem
	gpgme_free(data_tmp);
	
	/*DO IT ONLY IF YOU CALLED THE GPGME_RESULT_REF BEFORE! DON'T DO IT TO DE-ALLOCATE THE RESULT! IT IS DONE AUTOMATICALLY WITH THE GPGME_RELEASE OF THE CONTEXT WHERE IT WAS CREATED!*/
	//we don't need the fingerprint anymore... we can unreference the result!
	////gpgme_result_unref(temp_genkey_result);
		
	//let's unref even the searched key. The search returned a reference and we need to unref it!
	gpgme_key_unref(public_key_OMN_slave_group);
	gpgme_key_unref(secret_key_OMN_slave_group);
	gpgme_key_unref(public_key_OMN_master);
	gpgme_key_unref(secret_key_OMN_master);

	//let's destroy the data objects to free the memory
	//gpgme_data_release(cleartext);

	//let's destroy the contexts..
	gpgme_release(encrypt_ctx);


	return 0;

}
