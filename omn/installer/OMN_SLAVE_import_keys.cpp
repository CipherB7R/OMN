#include "../OMN_common.h"




int main(int argc, char** argv){

	


	//(possible) error variables. Need them cause it's the way to check if a decryption or verification action fails (bad signature, bad message etc.).
	gpgme_error_t error; //will contain err_code and err_source. We will extract only err_code
	gpgme_err_code_t error_code; //will contain error code of "error" variable. Taken with gpgme_err_code(gpgme_error_t err).

	//data exchange variables.
	gpgme_data_t cleartext;
	gpgme_off_t offset;
	gpgme_data_type_t type; //type of content of a data buffer. Fill it with gpgme_data_identify(gpgme_data_t dh).


	//first things first! Let's initialize gpgme!
	init_gpgme();



	//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
	
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



	//let's import an RSA public and private keypair FROM A FILE!
	//first off, let's create a gpgme data object from file.
	gpgme_data_t keys_to_be_imported;

	if(gpgme_data_new_from_file(&keys_to_be_imported, "exported_keys_for_OMNslave.txt", 1) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to open \"exported_keys_for_OMNslave.txt\". Maybe it doesn't exist or is already opened by some other program. Hence, we failed to create a gpgme data object\n");
		exit(-1);
	}


	//let's import em!
	if(gpgme_op_import(encrypt_ctx, keys_to_be_imported) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to import keys from file\n");
		exit(-1);
	}
	
	//now we can print what we have imported!
	gpgme_import_result_t import_results = gpgme_op_import_result(encrypt_ctx);
	std::list<std::pair<std::string, int>> list_of_imported_keys;
		

	if(import_results != NULL) {
		fprintf(stdout, "Successfully imported %d keys (we considered %d)!\n", import_results->imported, import_results->considered);
		int temp_j = 0;
		gpgme_import_status_t temp_import = import_results->imports;

		char* secret_key_fpr = NULL;
		char* public_key_fpr[2] = {NULL};
		
		int i = 0;


		while(temp_import != NULL) {
			if(temp_import->result == GPG_ERR_NO_ERROR) {

				int is_secret;

				fprintf(stdout, "#%d imported ", temp_j);
				if(temp_import->status & GPGME_IMPORT_SECRET) { //bitwise AND, will result in a "true" ("non zero value" in C) if the key was secret.
					fprintf(stdout, "secret ");
					secret_key_fpr = temp_import->fpr;
					is_secret = 1;
				}
				else {
					fprintf(stdout, "public ");
					if(i<2) {
					public_key_fpr[i] = temp_import->fpr;
					i++;
					}
					is_secret = 0;
				}
				fprintf(stdout, "key: %s\n", temp_import->fpr);

				//Gotta trust it now...
				//let's get the key first.	
				bool authorize_yes = yes_or_no_choice("Do you want to really trust it?");
				
				if(!authorize_yes) {
					fprintf(stdout, "Can't complete the import of OMN GPG keypairs. OMN won't work without them. Retry!\n");
					exit(-1);
				}

				
				list_of_imported_keys.push_back(std::pair<std::string, int>(std::string(temp_import->fpr), is_secret));


			}
			temp_j++; 
			temp_import = temp_import->next;
		}

		//before calling another operation, and thus invalidating the temp_import addresses, do this...
		
		//what's the master one? The one slaves don't have as secret!
		std::string possible_1 = std::string(public_key_fpr[0]);
		std::string possible_2 = std::string(public_key_fpr[1]);
		std::string should_not_be = std::string(secret_key_fpr);
		
		
		std::string master_fpr;
		std::string slave_grp_fpr;
		
		//std::string master_fpr = possible_1 == should_not_be ? std::string(possible_2) : std::string(possible_1);
		if(possible_1 == should_not_be) {
			master_fpr = std::string(possible_2);
			slave_grp_fpr = std::string(possible_1);
		}
		else {
			master_fpr = std::string(possible_1);
			slave_grp_fpr = std::string(possible_2);
	       	}

		//now let's trust them.
		//let's fire up the finite state machine to trust it!
		for(std::pair<std::string, int>& pair_fpr_isSecret: list_of_imported_keys) {
			//we need a data_t object to contain the output of the crypto engine.
			gpgme_data_t out;

			gpgme_key_t tmp_key_OMN;

			//now let's get the key, secret = 0 so we take only the PUBLIC key.	
			if(gpgme_get_key(encrypt_ctx, pair_fpr_isSecret.first.c_str(), &tmp_key_OMN, pair_fpr_isSecret.second) != GPG_ERR_NO_ERROR) {
				fprintf(stderr, "Failed to retrieve imported key from import result, fingerprint %s\n", pair_fpr_isSecret.first.c_str());
				exit(-1);
			} else {
				if(tmp_key_OMN == NULL) {
					fprintf(stderr, "FAILED TO RETRIEVE IMPORTED KEY, FINGERPRINT %s\n", pair_fpr_isSecret.first.c_str());
					//should we delete it?
					exit(-1);
				}
			}

			if(gpgme_data_new(&out) != GPG_ERR_NO_ERROR) {
				fprintf(stderr, "Failed to create new gpgme data object for output of crypto engine!\n");
				exit(-1);
			}

			if(gpgme_op_interact(encrypt_ctx, tmp_key_OMN, 0, trust_interaction_func_automatic, out, out) != GPG_ERR_NO_ERROR) {
				fprintf(stderr, "Failed to trust key with fingerprint %s\n", tmp_key_OMN->fpr);
				exit(-1);
			}
			
			fprintf(stdout, "Key %s successfully trusted to ULTIMATE trust level.\n", tmp_key_OMN->fpr);
			
			gpgme_data_release(out);
			gpgme_key_unref(tmp_key_OMN);
			
		}

		list_of_imported_keys.clear();
		
		

		

		std::string omn_filepath = std::string(getenv("HOME")) + "/" + std::string(OMN_DIRECTORY);
		
		struct stat st = {0};
		if(stat(omn_filepath.c_str(), &st) == -1) {
			mkdir(omn_filepath.c_str(), 0775);
		}
		
		std::string complete_filepath = omn_filepath + "/" + std::string(OMN_CFG_FILENAME);
		FILE* fp = fopen(complete_filepath.c_str(), "w");
		if(fp == NULL) fprintf(stderr, "Failed to open file!\n");
		else {
			fprintf(stdout, "Give me a lan name (max 127 characters, alphanumerical, only special \"_\" is allowed. NO WHITESPACES!)... ");
			char lan_name[128] = "";
			scanf("%127s", lan_name);
			//now let's create a keypair just for this slave!
				
			
			fprintf(stdout, "Generating NORM id... MAKE SURE YOU ACCEPT A NUMBER THAT YOU HAVE NEVER SEEN BEFORE!\n");
			
			fprintf(stdout, "Press enter to continue...\n");
			getchar();

			NormNodeId generated_NORMID = generate_local_id();
			fprintf(stdout, "Generated NORM id %u. ", generated_NORMID);
			while(!yes_or_no_choice("Keep it?")) {
				generated_NORMID = generate_local_id();
				fprintf(stdout, "Generated NORM id %u. ", generated_NORMID);
			}
			
			fprintf(stdout, "Now we will create a GPG keypair just for this slave!\n Remember: no password should be provided, since slaves act autonomously and can't insert passwords!\n");
			fprintf(stdout, "Press enter to continue...\n");
			getchar();

			//let's generate an RSA public key keypair, with userid "OMN slave " + the string for this LAN, reasonable expire time (0, page 63 gpgme manual),   
			//and set it so we can encrypt, sign and auth with it.
			std::string uid = std::string("OMN slave ") + std::string(lan_name) + std::string(" ") + std::to_string(generated_NORMID);
			if(gpgme_op_createkey(encrypt_ctx, uid.c_str(), "rsa", 0, 0, NULL, GPGME_CREATE_ENCR | GPGME_CREATE_SIGN | GPGME_CREATE_AUTH | GPGME_CREATE_NOPASSWD) != GPG_ERR_NO_ERROR) {
				fprintf(stderr, "Failed to create createkey job for Slave's keys\n");
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
			
			
			fprintf(fp, "master:%s\nslave_group:%s\nlocal_slave:%s\nlan_name:%s\nNORM_ID:%u\n", master_fpr.c_str(), slave_grp_fpr.c_str(), temp_genkey_result->fpr, lan_name, generated_NORMID);

			fprintf(stdout, "Successfully created OMN config file %s\n", complete_filepath.c_str());
			fclose(fp);


			//now we need to export the generated public key of this OMN slave. We need it in order to be able
			//to import it back in the master's PC!


			fprintf(stdout, "Let's try to retrieve the generated public key of this slave from the keychain, in order to export it!\n");
			gpgme_key_t public_key_OMN_slave;

			//now let's get the key, secret = 0 so we take only the PUBLIC key.	
			if(gpgme_get_key(encrypt_ctx, temp_genkey_result->fpr, &public_key_OMN_slave, 0) != GPG_ERR_NO_ERROR) {
				fprintf(stderr, "Failed to retrieve createkey result (public key!)\n");
				exit(-1);
			} else {
				if(public_key_OMN_slave == NULL) {
					
					fprintf(stderr, "FAILED TO RETRIEVE PUBLIC KEY FOR OMN SLAVE (personal)\n");
					//should we delete it?
					exit(-1);
				}

			}
			

			fprintf(stdout, "Slave personal key retrieved! Fingerprint %s --- Is secret? %d\n", public_key_OMN_slave->fpr, public_key_OMN_slave->secret);

			//now let's export it.
			gpgme_data_t keys_to_be_exported;

			gpgme_key_t v_exporting_pubkeys[2] = {public_key_OMN_slave, NULL};
			
			//let's initialize the data buffer.
			//we need a gpgme_data_t object... let's create it with gpgme_data_new... this function will return its handle inside the variable cleartext.
			if(gpgme_data_new(&keys_to_be_exported) != GPG_ERR_NO_ERROR) {
				fprintf(stderr, "Failed to create new gpgme data object!\n");
				exit(-1);
			}


			//public key (only it!).
			if(gpgme_op_export_keys(encrypt_ctx, v_exporting_pubkeys, 0, keys_to_be_exported) != GPG_ERR_NO_ERROR) {
				fprintf(stderr, "Failed to export slave's pubkey\n");
				exit(-1);
			}



			//...and let's store it into a file.
			size_t length_of_keys_data;
			char* data_tmp = gpgme_data_release_and_get_mem(keys_to_be_exported, &length_of_keys_data);
			
			if(data_tmp == NULL) {
				fprintf(stderr, "Failed to release and get export memory\n");
			} else {
				//let's store it into a file!
				std::string export_filename = std::string("exported_slave_") + std::string(lan_name) + std::string("_GPGpubkey.txt");
				FILE* fp = fopen(export_filename.c_str(), "wb");
				if(fp == NULL) fprintf(stderr, "Failed to open file!\n");
				else {

					fwrite(data_tmp, sizeof(char), length_of_keys_data, fp);
					fprintf(stdout, "Successfully printed current slave public key data inside file %s!\n Take it to master's PC and run the command to import it!\n", export_filename.c_str());
					fclose(fp);
				}
			}

			gpgme_key_unref(public_key_OMN_slave);


		}

	}

		
	//let's destroy the data objects to free the memory
	gpgme_data_release(keys_to_be_imported);

	//let's destroy the contexts..
	gpgme_release(encrypt_ctx);


	return 0;

}
