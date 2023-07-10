#include "OMN_slaves.h"


char * get_directory_where_to_save_results(Command cmd, int * len) {
	switch(cmd.codename) {
		case NMAP:
			//directory is located inside opt_data, null terminated string!...
			if(cmd.len > 0) {
				*len = cmd.len;
				//gotta copy in new memory... Command opt_data will get freed!!!
				char *tmp = (char*) malloc(*len);
				if(tmp == NULL) {
					fprintf(stderr,"Failed to allocate memory for extracting directory from command! NULL!\n");
					exit(-1);
				} else {
					//just copy cmd.optdata inside this!
					if(cmd.len < RESULT_NAME_LENGTH) fprintf(stderr, "BADLY FORMATTED NMAP COMMAND! OPT_DATA DOES NOT CONTAIN STATIC FIELD FOR RESULT NAME!\n");
					else {
						if(cmd.len > RESULT_NAME_LENGTH) 
							fprintf(stdout, "BADLY FORMATTED NMAP COMMAND! OPT_DATA IS LONGER THAN %d BYTES! TAKING ONLY THE FIRST PART!\n", RESULT_NAME_LENGTH);
						memcpy(tmp, cmd.opt_data, RESULT_NAME_LENGTH);
						tmp[*len - 1] = '\0'; //just to be safe...
					}
				}
				return tmp;
			}
			break;
		case SEND_FILE: 
			{

				opt_data_SEND_FILE tmp_optdata;
				opt_data_SEND_FILE_get(cmd, tmp_optdata);
				char *tmp = (char*) malloc(RESULT_NAME_LENGTH);
				if(tmp == NULL){
					fprintf(stderr,"Failed to allocate memory for extracting directory from command! NULL!\n");
					exit(-1);
				} else {	
					memcpy(tmp, tmp_optdata.directory, RESULT_NAME_LENGTH);
					return tmp;
				}	
			}
			break;
		default:
			fprintf(stderr,"We tried to get a directory name from the command, but the command isn't part of the set that requires so!!\n");

	}


	return NULL;
}

//we'll just build a string like "SCAN_DD_MM_YYYY_hh_mm", with filename its sha256 hash! Just to have a space to save them! THIS IS JUST BACKUP!
char * get_default_directory_name(Command cmd, int * len) {
	//we need 17 chars for "_DD_MM_YYYY_hh_mm"
	int to_be_allocated = 17;
	char * constructing;

	to_be_allocated += 6 ; //"RESULT" prefix.

	to_be_allocated += 1; //'\0' terminator.
	
	constructing  = (char *) malloc(to_be_allocated);
	
	if(constructing == NULL) {
			fprintf(stderr,"Failed to allocate memory for creating default directory name!\n");
			exit(-1);
	}
	
	std::chrono::system_clock::time_point right_now = std::chrono::system_clock::now();
	time_t tt = std::chrono::system_clock::to_time_t(right_now);
	tm local_tm = *localtime(&tt);

	sprintf(constructing, "RESULT_%d_%d_%d_%d_%d",local_tm.tm_mday, local_tm.tm_mon + 1, local_tm.tm_year + 1900, local_tm.tm_hour, local_tm.tm_min);

	constructing[to_be_allocated - 1] = '\0';

	*len = to_be_allocated;
	return constructing;	
}



//called after gpgme_init(), works only for slaves (cause it gets the slave's secret key but can't get master's one!)
//It initializes gpgme slave's context, retrieving slave's keypair and the master's pubkey.
void SlaveCryptoCtx::init_crypto_context() {


	//creating the context.
	if(gpgme_new(&(this->gpgme_context)) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create a new context\n");
		exit(-1);
	}

	//set the OpenPGP protocol for the created context
	if(gpgme_set_protocol(this->gpgme_context, GPGME_PROTOCOL_OpenPGP) != GPG_ERR_NO_ERROR) {

		fprintf(stderr, "Failed to set openPGP protocol in new context\n");
		exit(-1);
	}

	//let's use ascii armor too (Radix64 algorythm to produce base64 output)
	gpgme_set_armor(this->gpgme_context, 1);	
	
	//now let's retrieve the keys. We first need to retrieve their fingerprints from the config file.
	char master_key_fpr[FINGERPRINT_LENGTH] = {0};
	char slaveGroup_key_fpr[FINGERPRINT_LENGTH] = {0};
	char slavePersonal_key_fpr[FINGERPRINT_LENGTH] = {0};
	char lan_name[LAN_NAME_LENGTH] = {0};

	std::string omn_filepath = std::string(getenv("HOME")) + "/" + std::string(OMN_DIRECTORY);
	std::string complete_filepath = omn_filepath + "/" + std::string(OMN_CFG_FILENAME);
	FILE* fp = fopen(complete_filepath.c_str(), "r");		
	if(fp == NULL) {
		fprintf(stderr, "Failed to open config file!\n");
		exit(-1); //can't continue without keys!
	} else {
		
		NormNodeId NORM_nodeid_for_this_node;
		
		fscanf(fp, "master:%40s\nslave_group:%40s\nlocal_slave:%40s\nlan_name:%127s\nNORM_ID:%u\n", master_key_fpr, slaveGroup_key_fpr, slavePersonal_key_fpr, lan_name, &NORM_nodeid_for_this_node);
		fprintf(stdout, "Here is the NORM ID of the slave: %u\n", NORM_nodeid_for_this_node);
		fprintf(stdout, "Here is the fingerprint of the master keypair: %s\n", master_key_fpr);
		fprintf(stdout, "Here is the fingerprint of the slaves keypair (group): %s\n", slaveGroup_key_fpr);
		fprintf(stdout, "Here is the fingerprint of the slave keypair (personal): %s\n", slavePersonal_key_fpr);
		fprintf(stdout, "Here is the name of the lan: %s\n", lan_name);
		
		this->local_NORMid = NORM_nodeid_for_this_node;
		
		this->my_lan_name = std::string(lan_name);
		
		fprintf(stdout, "Getting other slave personal key's fingerprints...\n");
                //now let's get each known slave personal key's fingerprint.
                bool shall_continue = true;
                while(shall_continue) {
                        char slave_lan_name[LAN_NAME_LENGTH] = {0};
                        char slave_key_fpr[FINGERPRINT_LENGTH] = {0};
			NormNodeId slave_normid;

                        if(fscanf(fp, "%127s %u %40s\n", slave_lan_name, &slave_normid, slave_key_fpr) == 3) {
				m_gpgKeyFingerprint_slaveNORMid[std::string(slave_key_fpr)] = slave_normid;
				m_slaveNORMid_slaveLanName[slave_normid] = std::string(slave_lan_name);			
				
				fprintf(stdout, "%s %u %s\n", slave_lan_name, slave_normid, slave_key_fpr);
                        
			} else {
                                shall_continue = false;
                        }

                }
		
				
		fprintf(stdout, "Successfully retrieved GPG key fingerprints from config file!\nLet's retrieve the real keys from GPG...\n");

		fclose(fp);
	}


	
	//now we can use the retrieved fingerprints to get the "real" keys from GPG, through GPGME.
	
	//now let's get the key for the slaves group, secret = 0 so we take only the PUBLIC key.	
	if(gpgme_get_key(this->gpgme_context, slaveGroup_key_fpr, &(this->public_key_OMN_slaveGroup), 0) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to load slaves group public key with fingerprint %s!\n", slaveGroup_key_fpr);
		exit(-1);
	} else {
		if(this->public_key_OMN_slaveGroup == NULL) {
			
			fprintf(stderr, "PUBLIC KEY FOR OMN SLAVES GROUP NOT FOUND. Searched fingerprint: %s\n", slaveGroup_key_fpr);
			//should we delete it?
			exit(-1);
		}

	}

	//let's get the secret key too (1)...
	if(gpgme_get_key(this->gpgme_context, slaveGroup_key_fpr, &(this->secret_key_OMN_slaveGroup), 1) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to load slaves group secret key with fingerprint %s!\n", slaveGroup_key_fpr);
		exit(-1);
	} else {
		if(this->secret_key_OMN_slaveGroup == NULL) {

			fprintf(stderr, "SECRET KEY FOR OMN SLAVES GROUP NOT FOUND. Searched fingerprint: %s\n", slaveGroup_key_fpr);
			//should we delete it?
			exit(-1);
		}

	}

	//now let's get the key for the local slave, secret = 0 so we take only the PUBLIC key.	
	if(gpgme_get_key(this->gpgme_context, slavePersonal_key_fpr, &(this->public_key_OMN_slavePersonal), 0) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to load slave (personal) public key with fingerprint %s!\n", slavePersonal_key_fpr);
		exit(-1);
	} else {
		if(this->public_key_OMN_slavePersonal == NULL) {
			
			fprintf(stderr, "PUBLIC KEY FOR OMN SLAVE (PERSONAL) GROUP NOT FOUND. Searched fingerprint: %s\n", slavePersonal_key_fpr);
			//should we delete it?
			exit(-1);
		}

	}

	//let's get the secret key too (1)...
	if(gpgme_get_key(this->gpgme_context, slavePersonal_key_fpr, &(this->secret_key_OMN_slavePersonal), 1) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to load slave (personal) secret key with fingerprint %s!\n", slavePersonal_key_fpr);
		exit(-1);
	} else {
		if(this->secret_key_OMN_slavePersonal == NULL) {

			fprintf(stderr, "SECRET KEY FOR OMN SLAVE (PERSONAL) GROUP NOT FOUND. Searched fingerprint: %s\n", slavePersonal_key_fpr);
			//should we delete it?
			exit(-1);
		}

	}


	//and master's public key too!
	if(gpgme_get_key(this->gpgme_context, master_key_fpr, &(this->public_key_OMN_master), 0) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to load master public key with fingerprint %s!\n", master_key_fpr);
		exit(-1);
	} else {
		if(this->public_key_OMN_master == NULL) {
			
			fprintf(stderr, "PUBLIC KEY FOR OMN MASTER NOT FOUND. Searched fingerprint: %s\n", master_key_fpr);
			//should we delete it?
			exit(-1);
		}

	}
	

	fprintf(stdout, "Key loaded! Fingerprint %s --- Is secret? %d\n", this->public_key_OMN_slaveGroup->fpr, this->public_key_OMN_slaveGroup->secret);
	fprintf(stdout, "Key loaded! Fingerprint %s --- Is secret? %d\n", this->secret_key_OMN_slaveGroup->fpr, this->secret_key_OMN_slaveGroup->secret);
	fprintf(stdout, "Key loaded! Fingerprint %s --- Is secret? %d\n", this->public_key_OMN_slavePersonal->fpr, this->public_key_OMN_slavePersonal->secret);
	fprintf(stdout, "Key loaded! Fingerprint %s --- Is secret? %d\n", this->secret_key_OMN_slavePersonal->fpr, this->secret_key_OMN_slavePersonal->secret);
	fprintf(stdout, "Key loaded! Fingerprint %s --- Is secret? %d\n", this->public_key_OMN_master->fpr, this->public_key_OMN_master->secret);
		
	//now let's load each of the other known slave's personal key!
	for(const auto& pair_gpgKeyFpr_slaveId: this->m_gpgKeyFingerprint_slaveNORMid) {
                gpgme_key_t tmp;

                if(gpgme_get_key(this->gpgme_context, pair_gpgKeyFpr_slaveId.first.c_str(), &(tmp), 0) != GPG_ERR_NO_ERROR) {
                        fprintf(stderr, "Failed to load slave public key with fingerprint %s!\n", pair_gpgKeyFpr_slaveId.first.c_str());
                        exit(-1);
                } else {
                        if(tmp == NULL) {

                                fprintf(stderr, "PUBLIC KEY FOR OMN SLAVE %s NOT FOUND. Searched fingerprint: %s\n", m_slaveNORMid_slaveLanName[pair_gpgKeyFpr_slaveId.second].c_str(), pair_gpgKeyFpr_slaveId.first.c_str());
                                //should we delete it?
                                exit(-1);
                        }

                }

                this->m_slaveId_gpgKey[pair_gpgKeyFpr_slaveId.second] = tmp;
                fprintf(stdout, "Key loaded! NormID: %u Fingerprint %s --- Is secret? %d\n", pair_gpgKeyFpr_slaveId.second, tmp->fpr, tmp->secret);

        }

	//we got everything, let the crypto ops begin!

	
}



bool SlaveCryptoCtx::remove_slave_pubkey(char* slave_pubkey_fpr, int& num_of_keys_deleted) {
	//if the command states that we should delete our own pubkey, then just exit the program and wait for a sysadmin to phisically show up.
	int num_of_keys_currently_deleted = 0;
	if(string(slave_pubkey_fpr) == string(public_key_OMN_slavePersonal->fpr)) {
		fprintf(stdout, "Just received termination OMN command. Terminating slave.\n");
		exit(0);
	}

	//if not, then search for the slave public key and delete it from the map.	
	if(m_gpgKeyFingerprint_slaveNORMid.find(string(slave_pubkey_fpr)) != m_gpgKeyFingerprint_slaveNORMid.end()) {

		NormNodeId to_be_deleted_normid = m_gpgKeyFingerprint_slaveNORMid[string(slave_pubkey_fpr)];
		
		if( gpgme_op_delete_ext(gpgme_context, m_slaveId_gpgKey[to_be_deleted_normid], GPGME_DELETE_FORCE) != GPG_ERR_NO_ERROR) {
			fprintf(stdout, "Failed to delete key with fingerprint: %s\n", m_slaveId_gpgKey[to_be_deleted_normid]->fpr);
			return false;
		}
		
		fprintf(stdout, "Successfully deleted key %s from keyring\n", m_slaveId_gpgKey[to_be_deleted_normid]->fpr);


		num_of_keys_currently_deleted = m_gpgKeyFingerprint_slaveNORMid.erase(string(slave_pubkey_fpr));

		m_slaveNORMid_slaveLanName.erase(to_be_deleted_normid);
		m_slaveId_gpgKey.erase(to_be_deleted_normid);

		rebuild_config_file();

	}
	return num_of_keys_currently_deleted == 1;
}

bool SlaveCryptoCtx::rebuild_config_file() {


		std::string omn_filepath = std::string(getenv("HOME")) + "/" + std::string(OMN_DIRECTORY);
		
		struct stat st = {0};
		if(stat(omn_filepath.c_str(), &st) == -1) {
			mkdir(omn_filepath.c_str(), 0775);
		}
		
		std::string complete_filepath = omn_filepath + "/" + std::string(OMN_CFG_FILENAME);
		FILE* fp = fopen(complete_filepath.c_str(), "w");


		if(fp == NULL) fprintf(stderr, "Failed to open config file!\n");
		else {
			
			fprintf(fp, "master:%s\nslave_group:%s\nlocal_slave:%s\nlan_name:%s\nNORM_ID:%u\n", public_key_OMN_master->fpr, public_key_OMN_slaveGroup->fpr, public_key_OMN_slavePersonal->fpr, my_lan_name.c_str(), local_NORMid);
			
			//add again all other slaves pubkeys fpr, lan names and normid triplets
			for(const auto& p: m_gpgKeyFingerprint_slaveNORMid) {

				fprintf(fp, "%s %u %s\n",
					       	m_slaveNORMid_slaveLanName[p.second].c_str(),
					       	p.second,
					       	p.first.c_str());

			}

			fclose(fp);
			return true;
		}

		return false;

}

bool SlaveCryptoCtx::import_new_slave_personal_key_public(char* gpg_import_memory, size_t size_import, int& num_of_new_keys_imported) {
	
	gpgme_data_t key_to_be_imported;

	num_of_new_keys_imported = 0;
	bool done_correctly = true;

	if(gpgme_data_new_from_mem(&key_to_be_imported, gpg_import_memory, size_import, 1) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create data object from memory\n");
		exit(-1);
	}

	
	//let's import em!
	if(gpgme_op_import(this->gpgme_context, key_to_be_imported) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to import keys from file\n");
		done_correctly = false;
	}
	
	//now we can print what we have imported!
	gpgme_import_result_t import_results = gpgme_op_import_result(this->gpgme_context);
	
	if(import_results != NULL && done_correctly) {
		fprintf(stdout, "Successfully imported %d keys (we considered %d)!\n", import_results->imported, import_results->considered);
	
		int temp_j = 0;
		
		gpgme_import_status_t temp_import = import_results->imports;
		
		std::list<std::string> list_of_imported_fingerprints;

		while(temp_import != NULL) {
			if(temp_import->result == GPG_ERR_NO_ERROR) {

				fprintf(stdout, "#%d imported ", temp_j);
				fprintf(stdout, "key: %s\n", temp_import->fpr);
				
				//shouldn't be secret and shouldn't be our personal slave key! GPGME_IM
				if(!(temp_import->status & GPGME_IMPORT_SECRET) && (temp_import->status & GPGME_IMPORT_NEW) && !(std::string(temp_import->fpr) == std::string(this->public_key_OMN_slavePersonal->fpr))) {
					list_of_imported_fingerprints.push_back(std::string(temp_import->fpr));
				} else {
					fprintf(stderr, "Ignoring imported secret key with fingerprint %s. Will not auth it.\n", temp_import->fpr);
				}

			}
			temp_j++; 
			temp_import = temp_import->next;
		}


		for(std::string& tmp_fpr : list_of_imported_fingerprints) {

			//let's get the key...
			gpgme_key_t imported_key;

			//always get the public key, this function is only meant to import the public keys of those slaves who have just been added to the OMN infrastructure!
			if(gpgme_get_key(this->gpgme_context, tmp_fpr.c_str(), &imported_key, 0) != GPG_ERR_NO_ERROR) {
				fprintf(stderr, "Failed to retrieve imported key with fingerprint %s\n", tmp_fpr.c_str());
			} else {
				if(imported_key == NULL) {	
					fprintf(stderr, "FAILED TO RETRIEVE IMPORTED KEY WITH FINGERPRINT %s\n", tmp_fpr.c_str());
				} else {
					
					gpgme_data_t out;
					
					if(gpgme_data_new(&out) != GPG_ERR_NO_ERROR) {
						fprintf(stderr, "Failed to create new gpgme data object for output of crypto engine!\n");
						exit(-1);
					}
					
					if(gpgme_op_interact(this->gpgme_context, imported_key, 0, trust_interaction_func_automatic, out, out) != GPG_ERR_NO_ERROR) {
						fprintf(stderr, "Failed to trust key with fingerprint %s\n", imported_key->fpr);
						exit(-1);
					}


					gpgme_data_release(out);
					//after authorizing, we need to add it to the OMN.cfg file.
					//We first get the lan name of the slave which this key pertains to.
					char lan_name_of_slave_imported_key[LAN_NAME_LENGTH] = {0};
					NormNodeId NORM_id_of_slave_imported_key;

					if(sscanf(imported_key->uids->name, "OMN slave %127s %u", lan_name_of_slave_imported_key, &NORM_id_of_slave_imported_key) == 2) {
						
						//check if we have it already...
						std::string lan_name_str_version = std::string(lan_name_of_slave_imported_key);

						if(get_slaveId_gpgKey(NORM_id_of_slave_imported_key) == NULL ) {

							//add it to the OMN.cfg file.
							std::string omn_filepath = std::string(getenv("HOME")) + "/" + std::string(OMN_DIRECTORY);
							std::string complete_filepath = omn_filepath + "/" + std::string(OMN_CFG_FILENAME);
							FILE* fp = fopen(complete_filepath.c_str(), "a");
							if(fp == NULL) fprintf(stderr, "Failed to open %s file!\n", complete_filepath.c_str());
							else {
								fprintf(fp, "%s %u %s\n", lan_name_of_slave_imported_key, NORM_id_of_slave_imported_key, tmp_fpr.c_str());
								fprintf(stdout, "OMN config file updated!\n");
								fclose(fp);
							}

							//and add it to the list.
							//gotta get another reference!
							gpgme_key_ref(imported_key);
							this->m_slaveId_gpgKey[NORM_id_of_slave_imported_key] = imported_key;
							this->m_gpgKeyFingerprint_slaveNORMid[std::string(tmp_fpr.c_str())] = NORM_id_of_slave_imported_key;
							this->m_slaveNORMid_slaveLanName[NORM_id_of_slave_imported_key] = std::string(lan_name_of_slave_imported_key);
						} else {
							fprintf(stdout, "You already imported this key! Ignoring...\n");

						}
					} else {
						fprintf(stdout, "FAILED TO RECOGNIZE LAN NAME OF IMPORTED KEY'S SLAVE (fingerprint: %s)!\nCAN'T ADD IT TO THE CONFIG FILE!", tmp_fpr.c_str());
					}
					
					num_of_new_keys_imported++;	

					gpgme_key_unref(imported_key);
				}

			}


		}

		done_correctly = true;
	}

	if(done_correctly) 
		fprintf(stdout, "Import executed with success.\n");
	else
	       	fprintf(stderr, "Import failed.\n");

	gpgme_data_release(key_to_be_imported);

	return done_correctly;
}


int SlaveCryptoCtx::get_number_of_known_slaves() {
        return this->m_slaveId_gpgKey.size();
}

gpgme_key_t SlaveCryptoCtx::get_slaveId_gpgKey(NormNodeId slaveId) {

	if(slaveId == this->local_NORMid) {
		return this->public_key_OMN_slavePersonal;
	} else {

		auto search = this->m_slaveId_gpgKey.find(slaveId);

		if(search != this->m_slaveId_gpgKey.end()) {
			return this->m_slaveId_gpgKey[slaveId];
		} else {
			return NULL;
		}

	}
	return NULL;
}



//will check if the GPG fingerprint in input is one of the slave's personal keys
bool SlaveCryptoCtx::is_fingerprint_known(std::string fpr) {
        
        auto search = this->m_gpgKeyFingerprint_slaveNORMid.find(fpr);
    
        if(search != this->m_gpgKeyFingerprint_slaveNORMid.end()) {
                return true;
        } else {
                return false;
        }

    
}





//we need to unreference the keys and destroy the context we created during the init function. 
//NOTE: A good remainder to programmers, that freeing other gpgme data (objects) with gpgme_free() and gpgme_data_release() is their responsibility!!!
void SlaveCryptoCtx::destroy_crypto_context() {
	

	//let's unref even the searched key. The search returned a reference and we need to unref it!
	gpgme_key_unref(this->public_key_OMN_slaveGroup);
	gpgme_key_unref(this->secret_key_OMN_slaveGroup);
	gpgme_key_unref(this->public_key_OMN_slavePersonal);
	gpgme_key_unref(this->secret_key_OMN_slavePersonal);
	gpgme_key_unref(this->public_key_OMN_master);
	
	for(const auto& kv: this->m_slaveId_gpgKey) {
                gpgme_key_unref(kv.second);
        }
	
	//let's destroy the contexts..
	gpgme_release(this->gpgme_context);

	this->m_gpgKeyFingerprint_slaveNORMid.clear();
	this->m_slaveNORMid_slaveLanName.clear();
        this->m_slaveId_gpgKey.clear();


}



Command OMN_subscribe(NormInstanceHandle instance, NormSessionHandle session, SlaveCryptoCtx& slave_crypto_ctx, Data_lockedon_master* master, std::vector<Data_slave>& otherSlaves) {



    Command possible_command;
    bool keepGoing = true;
    bool locked = false; //true if master contains a VALID normID, and we are waiting for Auth3 packet!

    master->his_NORMID = INVALID_ID; //we didn't find a master yet...


    fprintf(stdout, "OMN: Starting master research...\nProcess will last indefinitely...\n");
    
    Auth2 to_be_sent;
    char* payload_auth2 = NULL;
    NormObjectHandle h_NORMOBJECT_auth2 = NORM_OBJECT_INVALID;
    bool last_TX_Auth2_purged = true;

    //-----------------------------------------------//
    //we need this part for the Auth3 response timeout! For efficiency we will use the select() even without a timeout!
    struct timeval startingTime;
    struct timeval timeout;

    int retval;
   
    //HEY! Why is this commented? If you've already seen the master .c file, you might recognize this line too!
    //Don't worry, we need to start counting time only after we LOCK onto a master (we LOCK when we receive a valid Auth1 message).
    //ProtoSystemTime(startingTime);

    //let's get norm descriptor in order to not block when we call NormGetNextEvent()
    NormDescriptor fd_NORM = NormGetDescriptor(instance);
    //-----------------------------------------------//

    //let's cycle the NORM events till we pick up an Auth1 message:
    //NOTE! AUTH1 COULD BE A FORGED MESSAGE, WE MUST 'DROP THE LOCK' IF DISCOVERY_SLAVE_TIMEMOUT SECONDS HAVE PASSED AND WE
    //DIDN'T GET AN AUTH3 (command)!
    while (keepGoing){

	
    	//we need to use select() to check asyncronously if the norm thread has any events for us!
    	//We do this by telling select we want him to check if the NORM file descriptor
    	//is ready for a read (by adding him to the set of file descriptor we want to check
    	//for a "read ready" state), with a waiting timeout of 3 second!
    	
	//let's initialize the timeout struct for the select().
	//wait up to SELECT_TIMEOUT second to "select()" timeout.
    	timeout.tv_sec = SELECT_TIMEOUT;
   	timeout.tv_usec = 0;
	    
	//Now let's initialize the file descriptor read bucket!
	fd_set fdsetInput; 
	FD_ZERO(&fdsetInput); //we reset the bucket, everytime we want to check, cause the sets gets modified
       			      //in place to indicate which file descriptors are currently ready (manpage)
    	FD_SET(fd_NORM, &fdsetInput); //we add the NORM file descriptor to the set, cause we want to check him.
    
	//we don't want to check exceptional or write "ready" state for any fd, we leave those FD buckets as NULL.
	//we just want to check the input set!
	//the first one must be the highest file descriptor value in all buckets, plus 1...
	//ok... let's pass the timeout too and we ready to go! THIS CALL WILL NOT BLOCK!
	retval = select(fd_NORM+1, &fdsetInput, NULL, NULL, &timeout);


	//if retval is 1, that means fd_NORM has become ready for a read -> a NORM EVENT is waiting to be picked up!
	if(retval == -1) {
		fprintf(stdout, "SUBSCRIBE: select(): has returned an error\n"); //welp, can't do much!
	} else if(retval) { 

		NormEvent theEvent;
		
		//let's block till we get a NORM event!
		if (!NormGetNextEvent(instance, &theEvent)) continue; //if NORM doesn't return an event, it's not an error...
								      //just continue!
		
		switch (theEvent.type){
			case NORM_RX_OBJECT_COMPLETED: //oh... a new NORM object... Will it be a valid Auth1 or Auth3 message?
				{
					//We can receive two different messages...
					//based on if we received an Auth1 message already (locked) or not (not locked): 
					//
					//	Auth1 -> cause we are not locked onto a master
					//	OR
					//	Auth3 -> cause we ARE locked onto a master
					//
					//	NOTE: This can be used for DoS attacks... Flood of Auth1 messages make the "slaves"
					//	lock onto a "rogue" master for DISCOVERY_SLAVE_TIMEMOUT seconds.
					//
					if(!locked){ 
						fprintf(stdout, "SUBSCRIBE: Possible new OMN master found!\n");
						
						//let's check the data received... will it be a valid Auth1 message???
						*master = wrapper_verify_Auth1(&theEvent);

						//if the verify returns a valid master NORM id, then what we received 
						//was indeed a valid Auth1 message!
						if(master->his_NORMID != INVALID_ID){

							//we just send the Auth2
							fprintf(stdout, "SUBSCRIBE: AUTH1>>>Possible masterID: %d\nChallenge received: %d\n", master->his_NORMID, master->challengeReceivedFromHim);
							//start timeout timer. We will wait for DISCOVERY_SLAVE_TIMEMOUT seconds for an Auth3 message. After
							//this time, we will reset state (and revert to searching another valid Auth1 message)
							//TODO: consider to shorten the timeout length
    							ProtoSystemTime(startingTime);


							to_be_sent = build_Auth2(master, slave_crypto_ctx);
							h_NORMOBJECT_auth2 = send_Auth2(session, &to_be_sent, slave_crypto_ctx, &payload_auth2);
							//can't access Auth2 variable "to_be_sent" anymore!

							last_TX_Auth2_purged = false;
							
							fprintf(stdout, "SUBSCRIBE: Sent Auth2 message, waiting for Auth3 response!\n");
							//we are now locked onto a possible master!
							locked = true;
						} else {
							fprintf(stderr, "SUBSCRIBE: AUTH1>>>Received invalid Auth1 message.\n");
						}
					} else { //we are locked onto a possible master...
						 //waiting for his Auth3 for SUBSCRIBE_SLAVE_TIMEMOUT seconds!
						fprintf(stdout, "SUBSCRIBE: Received another message, possible new command (Auth3)!\n");
						if(verify_Auth3(&theEvent, session, slave_crypto_ctx, master, possible_command, otherSlaves)){
							//the verification was a success, we just break out of the loop.
							keepGoing = false;
							master->authed = true;
						}	
						
						//we must check if it was a valid command or not... Maybe it is just an Auth1
						//reply for an another new OMN node who just appeared!
					}
				} //end case NORM_RX_OBJECT_COMPLETED
				break;
			case NORM_REMOTE_SENDER_NEW:
				{
				fprintf(stdout, "SUBSCRIBE: New sender! Another master? Or a new slave perhaps... We don't mind\n");

				} //end case NORM_REMOTE_SENDER_NEW
				break;
			case NORM_TX_OBJECT_PURGED:
				fprintf(stdout, "SUBSCRIBE: Auth2 NORM OBJECT Purged!");
				//NORM just purged our Auth2 from sending queue!!!!
				if(!last_TX_Auth2_purged) {	
					free(payload_auth2);
					h_NORMOBJECT_auth2 = NORM_OBJECT_INVALID;
					last_TX_Auth2_purged = true;
				}
				break;
			default:
				TRACE("SUBSCRIBE: Got event type: %d\n", theEvent.type); 
		}  // end switch(theEvent.type)



	} else { //we enter there if retval == 0, which means select() has timed out while waiting for 
		 //NORM file descriptor to become read-ready!
		fprintf(stdout, "SUBSCRIBE: just a heads up, select() has timed out! Don't worry too much!\n");
	}

	//did we pass the DISCOVERY_SLAVE_TIMEMOUT seconds??? Let's check the clock now and compute how much time has passed
	//since we received the first Auth1 message!
	struct timeval currentTime;
	ProtoSystemTime(currentTime);
   	if(currentTime.tv_sec - startingTime.tv_sec > DISCOVERY_SLAVE_TIMEMOUT && locked) {
		//oh, we're inside here huh?
		//this means we need to UNLOCK slave from the current master, by resetting all variables pertaining to it!
		master->his_NORMID = INVALID_ID;
		master->challengeReceivedFromHim = -1;

		locked = false;
		if(!last_TX_Auth2_purged) {
			free(payload_auth2);
			NormObjectCancel(h_NORMOBJECT_auth2);
			h_NORMOBJECT_auth2 = NORM_OBJECT_INVALID;
			last_TX_Auth2_purged = true;
		}
	
		fprintf(stderr, "SUBSCRIBE: AUTH1>>>Slave timed out on waiting for Auth3 message from master. Unlocking slave!\n");
	};



    } //end while

    if(!last_TX_Auth2_purged) {
	    NormObjectCancel(h_NORMOBJECT_auth2);
	    h_NORMOBJECT_auth2 = NORM_OBJECT_INVALID;
	    free(payload_auth2);
	    last_TX_Auth2_purged = true;
    }
	
    fprintf(stdout, "Subscribe phase ended.\n");
    return possible_command;
}

/**
 * Sign with key of B (master) the data:
 * B (master's id), rB (random challenge received from the master) and rA (random challenge generated by the slave)
 */
gpgme_data_t sigA__B_rB_rA(SlaveCryptoCtx& slave_crypto_ctx, NormNodeId B, int rB, int rA){
	
	//first off, we need 2 new gpgme_data_t object:
	gpgme_data_t sig_for_auth2, cleartext;


	//empty cleartext that will contain all the three inputs of this functions, concatenated like this:
	// |B|rB|rA|	
	if(gpgme_data_new(&cleartext) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain cleartext for Auth2 message!\n");
		exit(-1);
	}

	//empty gpgme_data_t that will contain signature!
	if(gpgme_data_new(&sig_for_auth2) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain signature for Auth2 message!\n");
		exit(-1);
	}

	//Oook, we got the two empty data objects, let's fill 'em up!
	//First of all, let's fill the cleartext as we said before...
	if(gpgme_data_write(cleartext, &B, sizeof(NormNodeId)) == -1) {	
		fprintf(stderr, "Failed to copy master's NormNodeId inside cleartext data object, for Auth2 message!\n");
		exit(-1);
	} else {
		fprintf(stdout, "Successfully copied master's NORM id (%d) inside cleartext data object, for Auth2 message!\n", B);
	}

	if(gpgme_data_write(cleartext, &rB, sizeof(int)) == -1) {	
		fprintf(stderr, "Failed to copy random challenge sent by master inside cleartext data object, for Auth2 message!\n");
		exit(-1);
	} else {	
		fprintf(stdout, "Successfully copied random challenge (%d) sent by master inside cleartext data object, for Auth2 message!\n", rB);
	}

	if(gpgme_data_write(cleartext, &rA, sizeof(int)) == -1) {
		fprintf(stderr, "Failed to copy random challenge generated by slave inside cleartext data object, for Auth2 message!\n");
		exit(-1);
	} else {	
		fprintf(stdout, "Successfully copied random challenge (%d) generated by slave inside cleartext data object, for Auth2 message!\n", rA);
	}

	//just a check, better be a bit paranoid!
	size_t cleartext_should_be_this_bytes_long = sizeof(NormNodeId) + sizeof(int) + sizeof(int);
	size_t actual_size = gpgme_data_seek(cleartext, 0, SEEK_CUR);
	if(actual_size != cleartext_should_be_this_bytes_long) {
		fprintf(stderr, "Failed to write data to cleartext gpgme object correctly! Only wrote %ld bytes, should've wrote %ld!", actual_size, cleartext_should_be_this_bytes_long);
		exit(-1);
	}

	fprintf(stdout, "Successfully wrote and prepared data to cleartext gpgme object! Wrote %ld bytes!", actual_size);

	//oook, let's reset the cursor to point at the start of cleartext, otherwise we are going to sign 0 bytes of data!
	//(it signs starting from current pointer position)	
	gpgme_data_seek(cleartext, 0, SEEK_SET);

	//now we need to add the secret key of OMN slave (personal) to the "signers" list.
	if(gpgme_signers_add(slave_crypto_ctx.gpgme_context, slave_crypto_ctx.secret_key_OMN_slavePersonal) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to add slave's personal secret key as a signer!\n");
		exit(-1);
	}
	
	fprintf(stdout, "Successfully added slave's personal secret key as a signer\nNumber of keys used to sign: %d\n", 
			gpgme_signers_count(slave_crypto_ctx.gpgme_context));

	//ok we're ready to sign! Detached signature since we are going to send ONLY the signature (without cleartext!)
	if(gpgme_op_sign(slave_crypto_ctx.gpgme_context, cleartext, sig_for_auth2, GPGME_SIG_MODE_DETACH) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to sign Auth2 DATA!!!!\n");
		exit(-1);
	}

	//let's ripristinate (at the first byte) the pointer in the signature data_T object (right now is pointing at the last byte written!).
	gpgme_data_seek(sig_for_auth2, 0, SEEK_SET);


	gpgme_signers_clear(slave_crypto_ctx.gpgme_context);
	//we'll "free" in "gpgme terms" the gpgme_data_t sig_for_auth2 later... The user must use it before!
	//we still need to free the cleartext tho...
	gpgme_data_release(cleartext);

	//signature for auth2 contains only the signature!!!
	return sig_for_auth2;

	
}


Auth2 build_Auth2(Data_lockedon_master* master, SlaveCryptoCtx& slave_crypto_ctx) { //no need for previous state information, no need for input! We just need to generate a random challenge!
	Auth2 tmp;

	//random challenge for the master, by the slave. Since we here, for convenience, let's copy it even in the master Data struct!
	tmp.rA = generate_random_number();
	master->challengeSentToHim = tmp.rA;

	//now let's generate the signature. gpgme_data_t is a c pointer.
	tmp.sigA__B_rB_rA = sigA__B_rB_rA(slave_crypto_ctx, master->his_NORMID, master->challengeReceivedFromHim, master->challengeSentToHim);


	return tmp;
}

//it invalidates Auth2 msg!!!! Can't access sigA anymore (the gpgme_data_t object gets released and freed!)!
//Gotta save the sent payload till a purge event is received.
NormObjectHandle send_Auth2(NormSessionHandle session, Auth2* msg, SlaveCryptoCtx& slave_crypto_ctx, char** payload) {

	//we need to send a message concatenated like this: 
	//	msg.rA | msg.sigA__B_rB_rA
	
	//Let's do this... First we must know what size is msg.sigA__B_rB_rA...
	//We can tell it by releasing the gpgme_data_t object and getting the memory for it!
	size_t length_of_sig;
	char *signature_to_be_sent = gpgme_data_release_and_get_mem(msg->sigA__B_rB_rA, &length_of_sig);

	if(signature_to_be_sent == NULL) {	
		fprintf(stderr, "Failed to release gpgme data_t sigA__B_rb_rA object!!!!\n");
		exit(-1);
	}

	//now we allocate data for length_of_sig + sizeof(int)
	size_t length_of_payload = sizeof(int) + length_of_sig;
	*payload = (char*) malloc(length_of_payload);

	if(*payload == NULL) {	
		fprintf(stderr, "Failed to allocate space for payload (Auth2)!\n");
		exit(-1);
	}


	//now we can copy at the right place all the data.
	memcpy(*payload, &(msg->rA), sizeof(int));	
	memcpy(*payload + sizeof(int), signature_to_be_sent, length_of_sig);

	//payload is ready to be sent, what are we waiting for??
	NormObjectHandle auth2_sent = NormDataEnqueue(session, *payload, length_of_payload, NULL, 0); //no INFO (NULL and 0)
	

	fprintf(stderr, "Sent Auth2 message! Total bytes %ld\n", length_of_payload);

	//remember to free the allocated memory...
	gpgme_free(signature_to_be_sent);
	//free(payload);


	return auth2_sent;

}

/*
//Auth protocol, 1: B -> A :	rB
NormObjectHandle send_Auth1(NormSessionHandle session, Auth1 msg) {
	
	//Send Auth1 message "msg" via NORM, without signing and encrypting, without NORM_INFO.
	return NormDataEnqueue(session, (char*) &(msg), sizeof(Auth1), NULL, 0);

}
*/

/* DEPRECATED
bool _verify_Auth1(NormSessionHandle session, Auth1 msg) {


	return true;
}
*/

Data_lockedon_master wrapper_verify_Auth1(NormEvent* event) {
	
	Data_lockedon_master tmp;
	Auth1 tmpAuth;

	tmp.his_NORMID = INVALID_ID;

	NormObjectHandle obj = event->object;
	//1) object type MUST be NORM_OBJECT_DATA
	if(NormObjectGetType(obj) != NORM_OBJECT_DATA) return tmp;
	//2) NormSize MUST be sizeof(Auth1) bytes ONLY.
	if(NormObjectGetSize(obj) != sizeof(Auth1)) return tmp;
	
	//Can't verify much more
	//Let's generate a valid Data_lockedon_master struct
	tmp.his_NORMID = NormNodeGetId(NormObjectGetSender(obj));
	memcpy((void *) &tmpAuth, (void *) NormDataAccessData(obj),sizeof(Auth1));
	tmp.challengeReceivedFromHim = tmpAuth.rB;	
	
	return tmp;
	

}
























/**
 *	Function used to verify received data, in order to establish if it is a valid Auth3 message.
 *	IT DOES INDEED CHECK IF THE SENDER IS A VALID NASTER (E.g. the signature contained in it is valid).
 *	Generally, if it returns true the client will proceed to save the list of other nodes active in the session,
 *	execute the received command and then send back the response by pairing it with the received token!
 *
 *	\param event The NORM event, used to get the data and the NORM_ID of the master.
 *	\param session The NORM session in which we received the data, used to get the localID for GPG verification purposes.
 *	\param prev_authed_data The data we previously authenticated, it contains the master's NORMid and the challenge we sent him, used for GPG verification purposes
 *	\param command Will contain the received command, if the data in NORM event is a valid and authenticated Auth3 message.
 *
 *	\return true if data in NORM event is a valid Auth3 message, false otherwise. 
 */
bool verify_Auth3(NormEvent* event, NormSessionHandle session, SlaveCryptoCtx& slave_crypto_ctx, Data_lockedon_master* prev_authed_data, Command& command, std::vector<Data_slave>& otherSlaves) {


	/***************************************************************************************************************************/
	/*************************************************CHECKING GOOD FORMAT******************************************************/
	/***************************************************************************************************************************/

	bool is_auth3_signature_valid = false; //this alone doesn't speak nothing about auth3 authenticity! The next however yes...
	bool is_auth3_currently_valid = false; //can only change to true if the sanitizing and NORMid/challenge pair is present inside Auth3.

	NormObjectHandle obj = event->object;
	//1) object type MUST be NORM_OBJECT_DATA
	if(NormObjectGetType(obj) != NORM_OBJECT_DATA) {
		fprintf(stderr, "Message isn't an Auth3 master response. NormObject was not NORM_OBJECT_DATA.\n");
		return false;
	}
	
	//We can't say anything certain about the max size of an Auth3 response... It varies since signature and encryption is armored (base64) and since
	//the encrypted original payload is compressed and contains a list (its size varies in relation to the master's maximum stack size)
	//and a command (its opt_data's field length varies).
	//Let's just not process any Auth3 message longer than 1MB (This way, even with an ARMORED signature size, rounded to, 1KB, plus 8 bytes for size_t
	//WE should still have 1000KB - 1KB -> 999KB for the list of nodes: This means that we can have 999*1024/16 where 16 is the size of a pair
	//which is 2 longs; this ammounts to something like 999*2^10/2^4 = 999*2^6 = 999*64 ACTIVE SLAVES!)
	//But still, it's just a max to set a limit on the amount of data we try to decrypt and verify with GPG.	
	if(NormObjectGetSize(obj) >= (1024*1024)) {
		fprintf(stderr, "Message isn't an Auth3 master response. NormObject was not shorter than 1MB\n");
		return false;	
	}
	
	//We can say something about the minimum size of an Auth3 response: 
	//It must at least contain sizeof(size_t) bytes; the first sizeof(size_t) bytes represent the length of the cyphertext that follows them.
	//It must contain then 566 bytes; Generally a detached UNARMORED signature is 566 bytes long. This is the BARE minimum.
	//   OMN sends only ARMORED signatures, but we can use this information to create a lower boundary for the size of a valid Auth3 message.
	if(NormObjectGetSize(obj) < (sizeof(size_t) + 566)) {
		fprintf(stderr, "Message isn't an Auth3 master response. NormObject was not longer than %ld bytes\n", sizeof(size_t)+566);
		return false;
	}

	fprintf(stdout, "Message contained a correcly formatted Auth3 message...\n");
	//Can't verify much more without taking some data...
	
	//Let's generate a valid Auth3 struct
	const char* data = NormDataAccessData(obj);
	
	//1)let's get the length of cyphertext:
	//	We must sanitize it before using it in the program, it must be:
	//	a) > 0
	//	b) sizeof(size_t) + length_of_cyphertext < NormObjectGetSize(obj) --> the last byte of the list must be contained inside the buffer:
	//									      can't read beyond boundaries of NormObject data.
	//	c) NormObjectGetSize(obj) - (sizeof(size_t) + length_of_cyphertext) >= 566 --> There should be enough space for a signature after it.
	size_t length_of_cyphertext = 0;
	memcpy((void *) &length_of_cyphertext, (void *) data, sizeof(size_t));
	//a
	if(length_of_cyphertext <= 0) {	
		fprintf(stderr, "ERROR during auth3 sanitizing! Cyphertext length %ld is not valid:  must be positive!\n", length_of_cyphertext);
		return false;
	}
	//b
	size_t tmp_sum = 0;
	if(__builtin_uaddl_overflow(sizeof(size_t), length_of_cyphertext, &tmp_sum)) {
		fprintf(stderr, "Overflow occured when trying to sanitize Auth3 messsage. Size of cyphertext: %ld. Size of length:%ld.\n",
				length_of_cyphertext, sizeof(size_t));
		return false;
	}
	if(tmp_sum >= NormObjectGetSize(obj)) {	
		fprintf(stderr, "ERROR during auth3 sanitizing! Cyphertext length %ld suggests a possible read out of boundaries, ABORTING!\n", length_of_cyphertext);
		return false;
	}
	//c
	size_t size_of_possible_signature = 0;
	if(__builtin_usubl_overflow(NormObjectGetSize(obj), tmp_sum, &size_of_possible_signature)) {
		fprintf(stderr, "Overflow occured when trying to sanitize Auth3 messsage. Size of cyphertext + length: %ld. Size of NORM object:%ld.\n",
				tmp_sum, NormObjectGetSize(obj));
		return false;
	}
	if(size_of_possible_signature < 566) {
		fprintf(stderr, "ERROR during auth3 sanitizing! Size of possible signature is shorter than the minimum size of %d bytes! IMPOSSIBLE!\n", 566);
		return false;
	}

	//OK, seems like the length of cyphertext is a valid message. Let's copy all the data inside the two data_t objects.
	Auth3 received_auth3;


	//empty gpgme_data_t that will contain signature!
	if(gpgme_data_new(&(received_auth3.sigB__list_COMM)) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain signature from Auth3 message!\n");
		exit(-1);
	}
	//let's fill it up with the real signature (the remaining part of the data: full data minus the first part, size_of_list + list)!
	if(gpgme_data_write(received_auth3.sigB__list_COMM, (void*) &(data[0 + sizeof(size_t) + length_of_cyphertext]), size_of_possible_signature) == -1) {
		fprintf(stderr, "Failed to copy received Auth3 signature part inside signature data object!\n");
		exit(-1);
	}
	fprintf(stdout, "Successfully wrote and prepared Auth3 signature data (received bytes: %ld), to be verified by OMN slave...\nSignature is long %ld bytes...\n", NormObjectGetSize(obj), gpgme_data_seek(received_auth3.sigB__list_COMM, 0, SEEK_CUR));
	//oook, let's reset the cursor to point at the start of the signature object, otherwise we are going to verify 0 bytes of data!
	//(it signs starting from current pointer position)
	gpgme_data_seek(received_auth3.sigB__list_COMM, 0, SEEK_SET);



	//empty gpgme_data_t that will contain encrypted payload!
	if(gpgme_data_new(&(received_auth3.pKAgroup__list_COMM)) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain cyphertext from Auth3 message!\n");
		exit(-1);
	}
	//let's fill it up with the real cyphertext (the first bytes of the data, minus the size_t field)!
	if(gpgme_data_write(received_auth3.pKAgroup__list_COMM, (void*) &(data[0 + sizeof(size_t)]), length_of_cyphertext) == -1) {
		fprintf(stderr, "Failed to copy received Auth3 cyphertext part inside cyphertext data object!\n");
		exit(-1);
	}
	fprintf(stdout, "Successfully wrote and prepared Auth3 cyphertext data (received bytes: %ld), to be decrypted by OMN slave...\nCyphertext is long %ld bytes...\n", NormObjectGetSize(obj), gpgme_data_seek(received_auth3.pKAgroup__list_COMM, 0, SEEK_CUR));
	//oook, let's reset the cursor to point at the start of the cyphertext object, otherwise we are going to decrypt 0 bytes of data!
	//(it decrypts starting from current pointer position)
	gpgme_data_seek(received_auth3.pKAgroup__list_COMM, 0, SEEK_SET);

	/***************************************************************************************************************************/
	/***************************************************VERIFICATION PHASE******************************************************/
	/***************************************************************************************************************************/
	
	//We need to:
	//1) decrypt the cyphertext, to get the cleartext.
	//2) verify the cleartext using the signature.	

	//1)...
	gpgme_data_t cleartext;
	
	//create a new empty object for this purpose!
	if(gpgme_data_new(&cleartext) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain cleartext from Auth3 message!\n");
		exit(-1);
	}

	//fill it up with the decrypted cyphertext.
	if(gpgme_op_decrypt(slave_crypto_ctx.gpgme_context, received_auth3.pKAgroup__list_COMM, cleartext) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to decrypt message!\n");
		
	} else {
		bool is_ciphertextValid = true;
		gpgme_decrypt_result_t decryption_result = gpgme_op_decrypt_result(slave_crypto_ctx.gpgme_context);
		//now we check that the recipient is one and one only: the public key of the slave.	
		if(decryption_result == NULL) 
		{
			fprintf(stderr, "Failed to recognize at least 1 encrypted text!\n");
			is_ciphertextValid = false;
		}
		else {

			if(decryption_result->recipients->next != NULL){
				fprintf(stderr, "The message was encrypted with more than 1 key, OMN ENCRYPTS ONLY WITH 1 KEY AT TIME!\n");
				is_ciphertextValid = false;
			}else if(decryption_result->recipients->pubkey_algo != GPGME_PK_RSA) {
				fprintf(stderr, "Ciphertext was NOT made with RSA public key algorithm!\n");
				is_ciphertextValid = false;
			}else if(decryption_result->wrong_key_usage){
				fprintf(stderr, "Ciphertext was made by using the slave's public key WRONGLY!\n");
				is_ciphertextValid = false;	
			}

			//last check: The ciphertext must have been encrypted with the slave's pubkey!
			//The results contain a keyid, not a fingerprint. We need to search for the fingerprint, and warn the user about possible duplicates!
			
			/* there MAY be a problem with this check (fingerprint(keyid) == fingerprint_of_masters_pubkey): It seems that gpg tries all secret keys inside the pc that it is running on:
			 * IF there are two keys in the same keyring with same keyid (lower 64 bits) there will be a collision! If one of the two keys has been compromised, an attacker
			 * could use this vulnerability to successfully encrypt and let the message pass as it was encrypted by the rightful key. We can only WARN the user about this!*/

			gpgme_key_t key_used_for_encryption;
			gpgme_error_t error_tmp = gpgme_get_key(slave_crypto_ctx.gpgme_context, decryption_result->recipients->keyid, &key_used_for_encryption, 0); //get the public key used for encryption, OMN SLAVES AND MASTERS have both so, since decryption went ok, this control should return at this point.i
			
			if(error_tmp != GPG_ERR_NO_ERROR && gpgme_err_code(error_tmp) == GPG_ERR_AMBIGUOUS_NAME) {

				fprintf(stderr, "***WARNING***: YOU HAVE TWO OR MORE KEYS WITH SAME KEYID AS THE PUBKEY USED FOR OMN SLAVES! CONSIDER CHANGING THEM!\n");
				//is_ciphertextValid = false; //It's been chosen to comment it out, ciphertext is still valid (but won't pass the auth protocol!) but if safety is considerable and the concern is real you may activate this line.
				
				//we must check them one by one, to see if there is slave's pubkey in them. Or we could just say the ciphertext is not valid. 
				//OR, since encryption is important only to secrecy, and the message was sent to me encrypted (i don't know and i can't know if it has been decripted half way to me!)
				//we can consider the message as valid (it arrived encrypted!)!
				//We can print the message for logging purposes and let the sysadmin discover who sent it to him!
			
			} else if(error_tmp != GPG_ERR_NO_ERROR){
					fprintf(stderr, "unknown error\n"); //we should find the key since the decryption completed successfully... It's some other type of error, like wrong variable considered or some other type.
					is_ciphertextValid = false;
			} else {
				//no error, we got only one key: is it really OMN's one? Or is it some other public key contained in this pc's keyring????
				
				if(!(strcmp(key_used_for_encryption->fpr, slave_crypto_ctx.public_key_OMN_slaveGroup->fpr) == 0 )) {
					fprintf(stderr, "Ciphertext was NOT made with the slaves group public key!\nfingerprint of used key:%s\nfingerprint should be: %s\n", key_used_for_encryption->fpr, slave_crypto_ctx.public_key_OMN_slaveGroup->fpr);
					is_ciphertextValid = false;
				} else {
				
					fprintf(stderr, "OK! Ciphertext was made with the slaves group public key!\nfingerprint of used key:%s\nfingerprint should be: %s\n", key_used_for_encryption->fpr, slave_crypto_ctx.public_key_OMN_slaveGroup->fpr);
				
				}
					
				gpgme_key_unref(key_used_for_encryption);
			}


			if(is_ciphertextValid)	{	//if we here, then it's all ok: cyphertext has been encrypted with just 1 key,
			       				//and it's the slaves group pubkey!
				
				//2)...
				fprintf(stdout, "All ok! Encryption was made with key with fingerprint %s\n", decryption_result->recipients->keyid);
				fprintf(stdout, "Decryption successfull... proceeding to verification...!\n");

				//Ok, now that we filled the data, let's verify it...	
				fprintf(stdout, "Successfully wrote and prepared data (%ld bytes) to cleartext gpgme object!\n", gpgme_data_seek(cleartext, 0, SEEK_CUR));

				//always reset the cursor after the writes!
				gpgme_data_seek(cleartext, 0, SEEK_SET);
				
				//let the verification ops begin!

				if(gpgme_op_verify(slave_crypto_ctx.gpgme_context, received_auth3.sigB__list_COMM, cleartext, NULL) != GPG_ERR_NO_ERROR) {
					fprintf(stderr, "Failed to complete verification of the Auth3 signature!\n");
					is_auth3_signature_valid = false; //let's re-state it!
				}

				gpgme_verify_result_t verification_results = gpgme_op_verify_result(slave_crypto_ctx.gpgme_context);

				if(verification_results == NULL) {
					fprintf(stderr, "Failed to get verify results!\n");
					is_auth3_signature_valid = false; //let's re-state it!
				}

				//now we must check this message was signed with the right key, AND ONLY WITH THAT KEY! WE CAN'T LET OTHERS SIGN IT!
				gpgme_signature_t possible_signature = verification_results->signatures;

				if(possible_signature == NULL) fprintf(stderr, "Failed to recognize at least 1 signature!\n");
				else {
					is_auth3_signature_valid = true;
					if(possible_signature->next != NULL){
						fprintf(stderr, "The message was signed by more than 1 key, OMN SIGNES ONLY WITH 1 KEY AT TIME!\n");
						is_auth3_signature_valid = false;
					}
					
					if(!(possible_signature->summary & GPGME_SIGSUM_VALID)){
						fprintf(stderr, "Signature is invalid! GPGME_SIGSUM_GREEN:%d - GPGME_SIGSUM_RED: %d - GPGME_SIGSUM_SYS_ERROR: %d - GPGME_SIGSUM_KEY_MISSING: %d\n",
								(possible_signature->summary & GPGME_SIGSUM_GREEN),
								(possible_signature->summary & GPGME_SIGSUM_RED),
								(possible_signature->summary & GPGME_SIGSUM_SYS_ERROR),
								(possible_signature->summary & GPGME_SIGSUM_KEY_MISSING)
						       );
						if(possible_signature->summary == 0x0) {
							//Undocumented: github.com/comotion/cpm/issues/27
							fprintf(stderr, "----------------------------------------------------\n");
							fprintf(stderr, "IMPORTANT!!!!!Are you sure you trusted the OMN keys?\n");
							fprintf(stderr, "----------------------------------------------------\n");
						
						}

						is_auth3_signature_valid = false;
					}

					if(!(strcmp(possible_signature->fpr, slave_crypto_ctx.public_key_OMN_master->fpr) == 0)) {
						fprintf(stderr, "Signature was NOT made with the master secret key!\n");
						is_auth3_signature_valid = false;
					}
					
					fprintf(stdout, "Signature was made with key with fingerprint %s\n", possible_signature->fpr);

					if(is_auth3_signature_valid) {
						fprintf(stdout, "SIGNATURE IS VALID!!!\n");
					}


				}



				if(is_auth3_signature_valid) {

					//let's get the cleartext data, in order to unstringify the list and check if the pair 
					//(our_localNORMid, challenge_we_sent) is present in it.
					size_t cleartext_data_length = 0;
					char* cleartext_data = gpgme_data_release_and_get_mem(cleartext, &cleartext_data_length);	
					
					//first off, let's sanitize the data.
					size_t command_offset = 0;
					long num_elem_list = 0;
					long index_of_our_token = 0;

					if(sanitize_auth3_cleartext(cleartext_data, cleartext_data_length, &command_offset)) {
						fprintf(stderr, "Auth3 cleartext data successfully sanitized.\n");
					

						//LET'S CHECK IF THE CLEARTEXT CONTAINS OUR LOCAL NORMID AND CHALLENGE.
						//ok, seems like the list size is correct. A read in destringify_list() will not go out of the boundaries. We can proceed.
						//std::vector<Data_slave> v_tmp;
						destringify_vector_of_Data_slave(otherSlaves, &(cleartext_data[0]));
						num_elem_list = otherSlaves.size();

						bool did_we_find_our_pair = false;
						//let's search for our challenge.
						for(long i = 0; i < num_elem_list && !did_we_find_our_pair; i++) {
							if(otherSlaves[i].his_NORMID == NormGetLocalNodeId(session)) {
								//we found our pair... Will it contain the challenge we sent???
								if(otherSlaves[i].challengeReceivedFromHim == (prev_authed_data->challengeSentToHim)) {
									did_we_find_our_pair = true;
									index_of_our_token = i;
								}
							}
						}
						
						if(!did_we_find_our_pair) {	
							fprintf(stderr, "ERROR! ERROR! ERROR! We received a possible replayed Auth3 object! We checked and it didn't contain the current challenge we generated for the session!\n");
							otherSlaves.clear(); //reset the vector... its data is useless!
						} else  is_auth3_currently_valid = true;

						if(is_auth3_currently_valid) {
							//ok last thing to do. If this is a valid auth3 message, without any problems, 
							//we can extrapolate the command...
							destringify_command(command, &(cleartext_data[command_offset]));
							//and the token! (it's placed starting 4 bytes before the command_offset)
							prev_authed_data->his_token = otherSlaves[index_of_our_token].token_for_him;
							fprintf(stdout, "node %d\n", otherSlaves[index_of_our_token].his_NORMID);
							prev_authed_data->num_of_active_slaves = num_elem_list;
							//we gotta delete the element inside otherSlaves that points to this slave...
							//The name of the vector is "otherSlaves", not "otherSlaves, Plus me!"!!!
							for(Data_slave d: otherSlaves) fprintf(stdout, "node %d : challenge %d\n", d.his_NORMID, d.token_for_him);
							otherSlaves.erase(otherSlaves.begin() + index_of_our_token);
							for(Data_slave d: otherSlaves) fprintf(stdout, "node %d : challenge %d\n", d.his_NORMID, d.token_for_him);
						}


					} //vector is destroyed here, out of scope!
				
					gpgme_free(cleartext_data);
				} else {
					gpgme_data_release(cleartext);
				}

			}
		}
	}

	//If is_auth3_signature_valid is true, it means the cleartext contained a message signed by a valid master.
	//WE STILL DON'T KNOW IF IT IS OR NOT AN AUTH3 VALID MESSAGE BECAUSE SOMEONE COULD BE REPLYING AN OLD AUTH3 MESSAGE THAT DOESN'T CONTAIN THE
	//CURRECT LOCAL NORMID AND THE CHALLENGE WE SENT THIS TIME!

		
	
	
	/***************************************************************************************************************************/
	//we need to release all gpgme objects!
	gpgme_data_release(received_auth3.pKAgroup__list_COMM);
	gpgme_data_release(received_auth3.sigB__list_COMM);

	return is_auth3_currently_valid;


}

bool sanitize_auth3_cleartext(char* cleartext, size_t length, size_t* command_offset) {
	//1) let's get the list size and the command opt_data size.
	//the list size is at the start of the data.
	long list_elements = 0;
	memcpy(&list_elements, cleartext, sizeof(long));
	//let's check it doesn't go out of boundaries
	if(list_elements < 1 ) { //can't be less than 1, at least 1 OMN slave (us) is active in the session!
		fprintf(stderr, "ERROR! Malformed auth3 cleartext: (NORMID,challenge) pair list must contain at least 1 pair.\n");
		return false;
	}
	//the list can't go out of the cleartext memory boundaries, THIS INQUALITY MUST BE TRUE: 
	//			 elem_num	          cmd_code      opt_len
	//			    vv			     vv	 	   v
	//  	size_of(list) + sizeof(long) <= length - sizeof(int) - sizeof(int)
	//IN ADDITION, there MUST be space for AT LEAST the token and the command's code and opt_length integer (to read them correctly!).
	size_t size_of_stringyfied_list_in_bytes = 0; //first member of the inequality
	size_t tmp_1 = 0;
	if(__builtin_umull_overflow(list_elements, sizeof(Data_slave), &tmp_1)) {
		fprintf(stderr, "ERROR! Malformed auth3 cleartext: failed to get size of list in bytes; OVERFLOW IN MULTIPLICATION!\nNum of elements: %ld\n", list_elements);
		return false;
	}
	if(__builtin_uaddl_overflow(tmp_1, sizeof(long), &size_of_stringyfied_list_in_bytes)) {	
		fprintf(stderr, "ERROR! Malformed auth3 cleartext: failed to get size of list in bytes; OVERFLOW IN ADDITION!\nNum of elements: %ld\n", list_elements);
		return false;
	}

	size_t remaining_space = 0; //second member of the inequality
	if(__builtin_usubl_overflow(length,  sizeof(Command_type) + sizeof(int), &remaining_space)) {	
		fprintf(stderr, "ERROR! Malformed auth3 cleartext: failed to get remaining bytes of cleartext data, that is, without stringified list's bytes; OVERFLOW IN SUBTRACTION!\nNum of elements: %ld\n", list_elements);
		return false;
	}
	if(size_of_stringyfied_list_in_bytes > remaining_space ) {	
		fprintf(stderr, "ERROR! Malformed auth3 cleartext: THE LIST SIZE IS INCOMPATIBLE WITH A GOOD AUTH3 MESSAGE!\nNum of elements: %ld\n", list_elements);
		return false;
	}
	

	//we can get the command offset by now. It is after the stringyfied list.
	/*
	if(__builtin_uaddl_overflow(size_of_stringyfied_list_in_bytes, sizeof(int), command_offset)) {	
		fprintf(stderr, "ERROR! Failed to get command offset for cleartext buffer; OVERFLOW IN ADDITION!\n");
		return false;
	}
	*/
	*command_offset = size_of_stringyfied_list_in_bytes;
	//Now we check the other possible "problem source", the opt_len field.
	int opt_len_field = 0;
	size_t offset = 0;

	if(__builtin_uaddl_overflow(size_of_stringyfied_list_in_bytes, sizeof(Command_type), &offset)) {	
		fprintf(stderr, "ERROR! Malformed auth3 cleartext: failed to get offset to command's optional field length in bytes; OVERFLOW IN ADDITION!\n");
		return false;
	}

	memcpy(&opt_len_field, &(cleartext[offset]), sizeof(int)); //it is found after the stringified list and after the command's code.
	
	//it can be 0, but not negative!
	if(opt_len_field < 0) {	
		fprintf(stderr, "ERROR! Malformed auth3 cleartext: command's optional field length is negative!\n");
		return false;
	}
	//If it is valid, the optional field must be contained in the remaining part of the cleartext's memory buffer (the last part).
	size_t bytes_before_cmd_optional_field = 0;
	if(__builtin_uaddl_overflow(size_of_stringyfied_list_in_bytes, sizeof(Command_type) + sizeof(int), &bytes_before_cmd_optional_field)) {
		fprintf(stderr, "ERROR! Malformed auth3 cleartext: failed to get number of bytes before command's optional field; OVERFLOW IN ADDITION!\n");
		return false;
	}
	size_t total_number_of_bytes_calculated = 0;
	if(__builtin_uaddl_overflow(bytes_before_cmd_optional_field, opt_len_field, &total_number_of_bytes_calculated )) {
		fprintf(stderr, "ERROR! Malformed auth3 cleartext: failed to get total bytes of cleartext according to the two variable fields' length; OVERFLOW IN ADDITION!\nBytes before command optional field: %ld; Optional field length: %d", bytes_before_cmd_optional_field, opt_len_field);
		return false;
	}
	if(total_number_of_bytes_calculated != length) {
		fprintf(stderr, "ERROR! Malformed auth3 cleartext: calculated length via variable fields' lengths does not concide with length of cleartext data!\n");
		return false;
	}

	//if all the controls haven't failed, the data is safe.
	return true;
	

}


std::string get_nmap_targets(bool only_ipv4) {
	
	struct ifaddrs * ptr_ifaddrs = NULL;
	bool not_first_one = false;

	std::string all_targets = std::string("");
	
	if(getifaddrs(&ptr_ifaddrs) == 0) {
		for(struct ifaddrs* ptr_entry = ptr_ifaddrs; ptr_entry != NULL; ptr_entry = ptr_entry->ifa_next) {
			
			std::string ipaddress_ascii;
			std::string netmask_ascii;
			std::string target;
			bool got_a_valid_target = false;

			//unsigned char FOR 0-255!!!!
			sa_family_t address_family = ptr_entry->ifa_addr->sa_family;
			if(address_family == AF_INET && only_ipv4) {
				//IPv4 addresses!
				if(ptr_entry->ifa_netmask != NULL && ptr_entry->ifa_addr != NULL) {
					
					//we need to get a number like /24
					//the netmask right now should be 4 chars (32 bit)
					//we iterate each one of them.
					
					char buffer2[INET_ADDRSTRLEN] = {0};
					//this function converts a uint32_t IP into human readable form!
					//seems like netmask is stored in big-endian format (upside down), so let's use inet_ntop to first get a string.
					inet_ntop(
							address_family,
							&((struct sockaddr_in*)(ptr_entry->ifa_netmask))->sin_addr,
							buffer2,
							INET_ADDRSTRLEN
							);
					
					unsigned char netmask_bytes[4] = {0};
					sscanf(buffer2, "%hhu.%hhu.%hhu.%hhu", &netmask_bytes[0],&netmask_bytes[1],&netmask_bytes[2],&netmask_bytes[3]);
					int real_netmask_cidr = 0;
					//let's calculate the CIDR notation netmask...
					for(int i = 0; i < 4; i++) {
						unsigned char current_byte = netmask_bytes[i];
						
						int sum = 0;
						if(current_byte != 0) { 
							while(current_byte%2 == 0) { //returns the shifted result and compares it too see if it is != 0 (true in C terms)
								sum++;
								current_byte /= 2;
							}
							real_netmask_cidr += 8 - sum;
						}

					}

					//we found the "CIDR suffix" netmask!
					netmask_ascii = std::string("/" + std::to_string(real_netmask_cidr));
					
					//now onto the address!
					char buffer[INET_ADDRSTRLEN] = {0};
					//this function converts a uint32_t IP into human readable form!
					inet_ntop(
							address_family,
							&((struct sockaddr_in*)(ptr_entry->ifa_addr))->sin_addr,
							buffer,
							INET_ADDRSTRLEN
							);

					ipaddress_ascii = std::string(buffer);

					//let's not scan 127.0.0.1
					if(!(ipaddress_ascii == std::string("127.0.0.1"))) {
						target = ipaddress_ascii + netmask_ascii;
						got_a_valid_target = true;
					}


				}
			} else if(address_family == AF_INET6 && !only_ipv4) { 
				//TODO: Already implemented, to be tested with IPv6 NORM!
				//IPv6!!!	
				if(ptr_entry->ifa_netmask != NULL && ptr_entry->ifa_addr != NULL) {
					
					//we need to get a number like /24
					//the netmask right now should be 16 chars (128 bits)
					//we iterate each one of them.
					
					//Nmap needs a target like this 3425:4234::0:1/32%eth0

					//now onto the address!
					unsigned char buffer[INET6_ADDRSTRLEN] = {0};
					//this function converts a uint32_t IP into human readable form!
					memcpy(
							buffer,
							&(((struct sockaddr_in6*)(ptr_entry->ifa_netmask))->sin6_addr),
							INET6_ADDRSTRLEN
							);

					uint32_t netmask_cidr6 = 0;
					//each one will be cyclicly shift one position to the left
					//till it is zero. At each cycle we will add 1 to the sum, 
					//effectively calculating the numbers of bit set (from the left)
					for(int i = 0; i < INET6_ADDRSTRLEN; i = i + sizeof(unsigned int) ) {
						unsigned int current;
						memcpy(&current, &(buffer[i]), sizeof(unsigned int));

						int sum_tmp = 0;
						if(current != 0) { 
							while(current%2 == 0) { //returns the shifted result and compares it too see if it is != 0 (true in C terms)
								sum_tmp++;
								current /= 2;
							}
							netmask_cidr6 += sizeof(unsigned int)*8 - sum_tmp;
						}
					}


					//we found the "CIDR suffix" netmask!
					netmask_ascii = std::string("/" + std::to_string(netmask_cidr6));
					
					//now onto the address!
					char buffer2[INET6_ADDRSTRLEN] = {0};
					//this function converts a uint32_t IP into human readable form!
					inet_ntop(
							address_family,
							&((struct sockaddr_in6*)(ptr_entry->ifa_addr))->sin6_addr,
							buffer2,
							INET6_ADDRSTRLEN
							);

					ipaddress_ascii = std::string(buffer2);

					//now we need the name of the interface...
					std::string interface = std::string(ptr_entry->ifa_name);



					target = ipaddress_ascii + netmask_ascii + "%" + interface;
					got_a_valid_target = true;

				}


			}

			if(got_a_valid_target) {
				if(not_first_one) {
					all_targets = all_targets + " "; //we need to separate en with a space, as NMAP man page/documentation!	
				}
				all_targets = all_targets + target; 
				not_first_one = true;	//the next round, add a , before putting a new target to the list...
			}
		}

	} else {
		fprintf(stderr, "Failed to get information regarding active network interfaces!\n");
		exit(-1);
	}

	freeifaddrs(ptr_ifaddrs);

	return all_targets;	

}

std::string get_nmap_options() {
	//for now, just do a verbose port SYN scan, for all active nodes (without -sn) with system sockets (No root required!)
	//TODO: next OMN version will have a config file just for this.
	return std::string("-v -p22");

}
std::string get_nmap_file_output_option() {
	//for now, just print it out in normal output.
	std::string path = std::string(OMN_TMP_DIRECTORY) + "/" + std::string(OMN_TMP_FILENAME_RESULT);
	return std::string("-oN " + path);
}


/*-----------------------------------------EXECUTE COMMAND PHASE----------------------------------------------*/
//MAY CONTAIN CRITICAL SECTIONS
Response process_command(Command cmd, char* lan_name, SlaveCryptoCtx& slave_crypto_ctx) {
	//simple routine, contains all possible ways to deal with all possible command codes.
	
	Response tmp_rsp;
	switch(cmd.codename) {
		case NMAP:
			{	//send results like "LAN_NAME | FILE"
				tmp_rsp.codename = NMAP_RESULT_FILE;
					
				//Ok, let's fork this process,
				pid_t ret_pid = fork();
				
				if(ret_pid == -1) {
					fprintf(stderr, "Failed to fork NMAP process. Terminating!\n");
					exit(-1);
				} else if(ret_pid == 0) {
					//Child process will execve' nmap
					std::string nmap_targets = get_nmap_targets(true);  //depends on interfaces attached to PCs...
					std::string nmap_options = get_nmap_options();	//depends on master's command...
					std::string nmap_file_output_option = get_nmap_file_output_option(); //Can save in xml or normal output mode. Based on master's command.

					std::string full_nmap_commandline = std::string("nmap " + nmap_targets + " " + nmap_options + " " + nmap_file_output_option + " >/dev/null 2>/dev/null");
					execlp("/bin/sh", "/bin/sh", "-c", full_nmap_commandline.c_str() , (char *) NULL);
					exit(-1); //if exec failed, exit!
				} else {
					//Main process (command-execution thread, this thread) will wait for the child process to exit,
					int status;
					waitpid(ret_pid, &status, 0);	
					if(WIFEXITED(status) != -1 && WIFEXITED(status) != 0) {
						//CAN'T PRINT FOR NORMAL REASONS IN THIS THREAD! fprintf(stdout, "NMAP scan terminated, getting result file contents...\n");
						
						//open the file and read its contents... save them after the LAN_NAME !
						size_t file_size = 0;
						char* result_contents = read_file(&file_size, OMN_TMP_FILENAME_RESULT, OMN_TMP_DIRECTORY);
						

						if(result_contents == NULL) {
							fprintf(stderr, "FAILED TO GET NMAP RESULT CONTENTS! CLOSING OMN!\n");
							exit(-1);
						}


						//contents can't be bigger than a couple of MB!!!
						if(file_size > NMAP_RESULT_FILE_MAX_SIZE) {
							fprintf(stderr, "NMAP FILE SIZE IS BIGGER THAN %d Bytes!! CLOSING OMN!\n", NMAP_RESULT_FILE_MAX_SIZE);
							exit(-1);
						}

							
						tmp_rsp.len = LAN_NAME_LENGTH + file_size; //we can use file_size as int at this point in the program... it doesn't exceed INT size cause it is < NMAP_RESULT_FILE_MAX_SIZE
						tmp_rsp.opt_data = (char *) malloc(tmp_rsp.len);
						

						if(tmp_rsp.opt_data == NULL){ 
							fprintf(stderr, "FAILED TO ALLOCATE MEMORY TO SEND RESPONSE! CLOSING OMN!\n");
							exit(-1);
						}	
						memcpy(tmp_rsp.opt_data, lan_name, LAN_NAME_LENGTH);
						memcpy(tmp_rsp.opt_data + LAN_NAME_LENGTH, result_contents, file_size);
						
						//we don't need the result contents anymore!
						free(result_contents);

						//we don't need the temporary result file too!!
						delete_file(OMN_TMP_FILENAME_RESULT, OMN_TMP_DIRECTORY);
						
					} else {
						fprintf(stderr, "Something went wrong during the execution of the NMAP scan! Exiting!\n");
						exit(-1);
					}

					//Will get the nmap result file contents and erase it.

				}
				

			}
			break;
		case SEND_RESULT_LIST:
			{
				//we need this for standardizing the opt_data field of a SEND_RESULT_LIST response.
				opt_data_RESULT_LIST opt_data_for_response;
				//check OMN folder directories... save all directories (NMAP past scans).
				OMN_slave_db_status db_status_of_results;
				//Proceed to build a list of filenames (hashes) present in each directory.
				db_status_of_results.retrieve_slave_db_status();
				//send the map "result -> list_of_filenames" to the master.
				size_t allocated_space_for_opt_data = 0;	
				opt_data_for_response.stringified_opt_data_RESULT_LIST_elements = db_status_of_results.stringify_slave_db_status(allocated_space_for_opt_data);
				//Generally speaking, the master will see this list and send us back a list of files he wants.
				
				memcpy(opt_data_for_response.lan_name_of_executor, lan_name, LAN_NAME_LENGTH);
				
				if(allocated_space_for_opt_data > (INT_MAX - LAN_NAME_LENGTH)) {
					fprintf(stderr, "A result list bigger than 3GB?? IMPOSSIBLE!\n");
					exit(-1);
				}
				
				if(allocated_space_for_opt_data > 0 && opt_data_for_response.stringified_opt_data_RESULT_LIST_elements != NULL) {
					tmp_rsp.codename = RESULT_LIST;
					tmp_rsp.len = allocated_space_for_opt_data + LAN_NAME_LENGTH;
					
					tmp_rsp.opt_data = (char*) malloc(tmp_rsp.len);
					if(tmp_rsp.opt_data == NULL){ 
						fprintf(stderr, "FAILED TO ALLOCATE MEMORY TO SEND RESPONSE! CLOSING OMN!\n");
						exit(-1);
					}	
						
					memcpy(tmp_rsp.opt_data, opt_data_for_response.lan_name_of_executor, LAN_NAME_LENGTH);
					memcpy(tmp_rsp.opt_data + LAN_NAME_LENGTH, opt_data_for_response.stringified_opt_data_RESULT_LIST_elements, allocated_space_for_opt_data);
					
					free(opt_data_for_response.stringified_opt_data_RESULT_LIST_elements);
				
				
				} else {
					tmp_rsp.codename = INVALID_RESPONSE;
					tmp_rsp.len = LAN_NAME_LENGTH;
					tmp_rsp.opt_data = (char *) malloc(tmp_rsp.len);
					memcpy(tmp_rsp.opt_data, lan_name, tmp_rsp.len);
					
				}


			}
			break;
		case SEND_FILE:
			{	//He sent us a command to get a file.
			       	//command must be exacly LAN_NAME_LENGTH + RESULT_NAME_LENGTH + SHA256_READABLE_LENGTH
				if(cmd.len != sizeof(opt_data_SEND_FILE)) {
					tmp_rsp.codename = INVALID_RESPONSE;
					tmp_rsp.len = LAN_NAME_LENGTH;
					tmp_rsp.opt_data = (char *) malloc(tmp_rsp.len);
					memcpy(tmp_rsp.opt_data, lan_name, tmp_rsp.len);

				} else {
					//If the command contained our LAN name, then it's on us to send that file!
					opt_data_SEND_FILE received_options;
					opt_data_SEND_FILE_get(cmd, received_options);
					
					if(std::string(received_options.lan_name_of_executor) != std::string(lan_name)) {
						//TODO: check if you have it and instead send a message based on that.
						tmp_rsp.codename = FILE_NOT_IN_THIS_NODE;
						tmp_rsp.len = LAN_NAME_LENGTH;
						tmp_rsp.opt_data = (char *) malloc(tmp_rsp.len);
						memcpy(tmp_rsp.opt_data, lan_name, tmp_rsp.len);
					} else {
						//We'll send it, just like we sending a NMAP result after a successfull NMAP scan

						//open the file and read its contents... save them after the LAN_NAME !
						size_t file_size = 0;

						//same for directory...
						std::string full_path = std::string(getenv("HOME")) + "/" + std::string(OMN_DIRECTORY) + "/" + std::string(received_options.directory);
						char* result_contents = read_file(&file_size, received_options.hash_filename, full_path.c_str());

						if(result_contents == NULL) {
							fprintf(stderr, "FAILED TO GET PAST NMAP RESULT FILE! SENDING FILE NOT FOUND RESPONSE!\n");
							tmp_rsp.codename = FILE_NOT_FOUND;
							tmp_rsp.len = LAN_NAME_LENGTH;
							tmp_rsp.opt_data = (char *) malloc(tmp_rsp.len);
							memcpy(tmp_rsp.opt_data, lan_name, tmp_rsp.len);
						} else {
							//send directly the encrypted file! (sign it with the new token, of course!)
							tmp_rsp.codename = REQUESTED_FILE; //the functions outside will see the response contain a valid REQUESTED_FILE codename, and will just send the opt_data content.

							//contents can't be bigger than a couple of MB!!!
							if(file_size > NMAP_RESULT_FILE_MAX_SIZE) {
								fprintf(stderr, "NMAP FILE SIZE IS BIGGER THAN %d Bytes!! CLOSING OMN!\n", NMAP_RESULT_FILE_MAX_SIZE);
								exit(-1);
							}

								
							tmp_rsp.len = file_size; //we can use file_size as int at this point in the program... it doesn't exceed INT size cause it is < NMAP_RESULT_FILE_MAX_SIZE
							tmp_rsp.opt_data = (char *) malloc(tmp_rsp.len);
							

							if(tmp_rsp.opt_data == NULL){ 
								fprintf(stderr, "FAILED TO ALLOCATE MEMORY TO SEND RESPONSE! CLOSING OMN!\n");
								exit(-1);
							}	
							memcpy(tmp_rsp.opt_data, result_contents, file_size);
							
							//we don't need the result contents anymore!
							free(result_contents);
						}
					}
				}

			}
			break;
		case IMPORT_SLAVE_PUBKEY:
			//TODO:just import from the opt_data.
			{
				pthread_mutex_lock(&gpgme_crypto_ctx_mutex);
				///////////////////////////////////////////////////////
				//////////////////CRITICAL SECTION/////////////////////
				///////////////////////////////////////////////////////
				int num_of_imported_keys = 0;
				slave_crypto_ctx.import_new_slave_personal_key_public(cmd.opt_data, cmd.len, num_of_imported_keys);
				///////////////////////////////////////////////////////
				////////////////END OF CRITICAL SECTION////////////////
				///////////////////////////////////////////////////////
				pthread_mutex_unlock(&gpgme_crypto_ctx_mutex);

				//build a simple response.
				tmp_rsp.codename = IMPORT_RESULT;
				tmp_rsp.len = sizeof(int) + LAN_NAME_LENGTH;
				tmp_rsp.opt_data = (char *) malloc(tmp_rsp.len);
				memcpy(tmp_rsp.opt_data, &num_of_imported_keys, sizeof(int));
				memcpy(tmp_rsp.opt_data + sizeof(int), slave_crypto_ctx.my_lan_name.c_str(), slave_crypto_ctx.my_lan_name.size());
			}	
			break;
		case DELETE_SLAVE_PUBKEY: 
			{
				pthread_mutex_lock(&gpgme_crypto_ctx_mutex);
				///////////////////////////////////////////////////////
				//////////////////CRITICAL SECTION/////////////////////
				///////////////////////////////////////////////////////
				//just try to remove the slave with the same fingerprint as in OPT_DATA
				int deleted_slave = 0; //0 for no, 1 for yes
				
				if(cmd.len == FINGERPRINT_LENGTH) {
					slave_crypto_ctx.remove_slave_pubkey(cmd.opt_data, deleted_slave);
				}
				///////////////////////////////////////////////////////
				////////////////END OF CRITICAL SECTION////////////////
				///////////////////////////////////////////////////////
				pthread_mutex_unlock(&gpgme_crypto_ctx_mutex);

				tmp_rsp.codename = REMOVE_SLAVE_RESULT;
				tmp_rsp.len = sizeof(int) + LAN_NAME_LENGTH;
				tmp_rsp.opt_data = (char *) malloc(tmp_rsp.len);
				memcpy(tmp_rsp.opt_data, &deleted_slave, sizeof(int));
				memcpy(tmp_rsp.opt_data + sizeof(int), slave_crypto_ctx.my_lan_name.c_str(), slave_crypto_ctx.my_lan_name.size());

			}
			break;
		case SAY_LAN:
			{
			tmp_rsp.codename = MY_LAN;
			tmp_rsp.len = LAN_NAME_LENGTH;
			tmp_rsp.opt_data = (char *) malloc(tmp_rsp.len);
			memcpy(tmp_rsp.opt_data, lan_name, tmp_rsp.len);

			}
			break;
		default:
			tmp_rsp.codename = INVALID_RESPONSE;
			tmp_rsp.len = LAN_NAME_LENGTH;
			tmp_rsp.opt_data = (char *) malloc(tmp_rsp.len);
			memcpy(tmp_rsp.opt_data, lan_name, tmp_rsp.len);
	}
	

	return tmp_rsp;
}


void process_RESPs(std::vector<EpkMaster_RESP> v_RESPs, Command cmd) {
		
	for(EpkMaster_RESP& el: v_RESPs) {
		//we treat em based on command.
		switch(cmd.codename) {

		case NMAP: 
			{
				//we save each one of them, always.
				int directory_length = 0;
				char* save_directory = get_directory_where_to_save_results(cmd, &directory_length);
				
				//save to file! We can't get the filename tho... let's use its sha256 hash!
				char hash_of_current_result[gcry_md_get_algo_dlen(GCRY_MD_SHA256) + 1] = ""; //+1 for null terminator!!!
				gcry_md_hash_buffer(GCRY_MD_SHA256, hash_of_current_result, el.ptr, el.size);
				char *hexstringed_hash = sha256_to_hexstring(hash_of_current_result);
				save_to_file(el.ptr, el.size, hexstringed_hash, save_directory);
				free(hexstringed_hash);

				fprintf(stdout, "SEND RESULT: Auth4 response saved from norm id %u.\n", el.source);	

				free(save_directory);	
			}
			break;
		case SEND_FILE:
			{
				//we save the only valid one (if it is a valid one...)
				int directory_length = 0;
				char* save_directory = get_directory_where_to_save_results(cmd, &directory_length);
				 
				opt_data_SEND_FILE opt_data_of_command;
				opt_data_SEND_FILE_get(cmd, opt_data_of_command);

				char hash_of_current_result[gcry_md_get_algo_dlen(GCRY_MD_SHA256) + 1] = ""; //+1 for null terminator!!!
				gcry_md_hash_buffer(GCRY_MD_SHA256, hash_of_current_result, el.ptr, el.size);
				char *hexstringed_hash = sha256_to_hexstring(hash_of_current_result);
	   
				//only save if the received file is the same as the expected one        
				bool save_result = std::string(opt_data_of_command.hash_filename) == std::string(hexstringed_hash);

				if(save_result) {
					save_to_file(el.ptr, el.size, hexstringed_hash, save_directory);
					fprintf(stdout, "SEND RESULT: Auth4 response saved from norm id %u.\n", el.source);
				 } else {
					fprintf(stdout, "SEND RESULT: Auth4 response IGNORED from norm id %u.\n", el.source);
				 }

				free(save_directory);	
					
				break;
			}
		case SAY_LAN:
		case IMPORT_SLAVE_PUBKEY:
		case SEND_RESULT_LIST:
		case DELETE_SLAVE_PUBKEY:
			//we DO NOT save them. EVER.
			fprintf(stdout, "Not saving this response.\n");
			break;
		default:
			fprintf(stdout, "Command was not recognized. Not saving its response.\n");

		}
		
		//just free the pointer.
		if(el.ptr_must_be_gpgme_freed) {
			fprintf(stdout, "Gpgme-");
			gpgme_free(el.ptr);
		} else free(el.ptr);
		fprintf(stdout, "freed an encrypted response RESP.\n");
	}

	v_RESPs.clear();


}



void* execute_command(void* params) {
	
	Execute_command_parms* p = (Execute_command_parms*) params;

	//try to get the lock, once you got it execute the command.
	//once the command is executed, produce a response, unlock the mutex and return.
	while(pthread_mutex_lock(&mutex_execute_command) != 0);
	///////////////////////////////////////////////////////
	//////////////////CRITICAL SECTION/////////////////////
	///////////////////////////////////////////////////////
	p->rsp = process_command(p->cmd, p->lan_name, *(p->slave_crypto_ctx));
	p->encryption_not_needed = p->rsp.codename == REQUESTED_FILE; //in all other cases, require encryption.
	p->response_avaliable = true;
	///////////////////////////////////////////////////////
	///////////////END OF CRITICAL SECTION/////////////////
	///////////////////////////////////////////////////////
	pthread_mutex_unlock(&mutex_execute_command); //unlock in all cases.
	
	/*
	fprintf(stdout, "------------------------------------------------\n");
	fprintf(stdout, "Command received\n");
	fprintf(stdout, "Codename: %d\n", p->cmd.codename);
	fprintf(stdout, "Optional data length: %d\n", p->cmd.len);
	fprintf(stdout, "Optional data: %s\n", p->cmd.opt_data);
	fprintf(stdout, "------------------------------------------------\n");
	*/

	return 0;


}



/*-----------------------------------------------------------------------------------------------------------*/


/*-------------------------------------------SEND RESULTS PHASE----------------------------------------------*/
//version to send the opt_data field of a response directly, as if it was the encrypted cyphertext of RESP!!!
//Used in SEND_FILE command sessions.
Auth4 build_Auth4_bypass_encryption(Data_lockedon_master* master, Response rsp, SlaveCryptoCtx& slave_crypto_ctx) {

	Auth4 tmp;
	
	//we need two more gpgme_data_t objects: one to contain the encrypted response, the other to contain the signature from the Auth4 message.
	//empty gpgme_data_t that will contain signature!
	if(gpgme_data_new(&(tmp.sigA__tB_pKBRESP)) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain signature for Auth4 message!\n");
		exit(-1);
	}
	
	//empty gpgme_data_t that will contain the encrypted cleartext_rsp! Since this is the bypassed version of the function, the encryption has already been done over the response.
	//WE just need to load that already encrypted response.
	if(gpgme_data_new_from_mem(&(tmp.pKB_RESP), rsp.opt_data, rsp.len, 1) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain encrypted RESP for Auth4 message (bypassed version for send file command)!\n");
		exit(-1);
	}

	
	//let's get the size of the cyphertext!	
	size_t size_of_pKB_RESP = gpgme_data_seek(tmp.pKB_RESP, 0, SEEK_END);
	//let's reset the cursor to point at the start of the cyphertext.
	gpgme_data_seek(tmp.pKB_RESP, 0, SEEK_SET);

	//We just "crafted" the pKB_RESP part. We are now able to "craft" the signature as sigSLAVE(token|pKB_RESP)
	//first off, we need another gpgme_data_t object, to contain the "cleartext" of the signature.
	gpgme_data_t cleartext_for_sig;

	if(gpgme_data_new(&cleartext_for_sig) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain cleartext for Auth4 signature!\n");
		exit(-1);
	}

	//then we fill it as token|pKB_RESP	
	if(gpgme_data_write(cleartext_for_sig, &(master->his_token), sizeof(int)) == -1) {	
		fprintf(stderr, "Failed to copy token inside cleartext (to be signed) data object, for Auth4 signature!\n");
		exit(-1);
	} else {	
		fprintf(stdout, "Successfully copied token (%d) inside cleartext data object, for Auth4 signature!\n", master->his_token);
	}
	
	//to write pKB_RESP inside the cleartext we first need to read the contents of the gpgme_data_t object that we crafted before.
	char* buf_pKB_RESP = NULL;
	buf_pKB_RESP = (char *) malloc(size_of_pKB_RESP);
	if(buf_pKB_RESP == NULL) {
		fprintf(stderr, "Failed to allocate space to read the encrypted part of Auth4 cleartext for signature object.\n");
		exit(-1);
	}
	if(gpgme_data_read(tmp.pKB_RESP, buf_pKB_RESP, size_of_pKB_RESP) == -1) {	
		fprintf(stderr, "Failed to read encrypted response data object, for Auth4 signature!\n");
		exit(-1);
	}
	gpgme_data_seek(tmp.pKB_RESP, 0, SEEK_SET); //always ripristinate the cursor!
	//we can now finish the filling of cleartext_for_sig
	if(gpgme_data_write(cleartext_for_sig, buf_pKB_RESP, size_of_pKB_RESP) == -1) {	
		fprintf(stderr, "Failed to copy encrypted response inside cleartext (to be signed) data object, for Auth4 signature!\n");
		exit(-1);
	} else {	
		fprintf(stdout, "Successfully copied encrypted response (%ld bytes) inside cleartext data object, for Auth4 signature!\n", size_of_pKB_RESP);
	}
	gpgme_data_seek(cleartext_for_sig, 0, SEEK_SET); //always ripristinate the cursor!


	//let's sign!
	//now we need to add the secret key of OMN slave (PERSONAL) to the "signers" list.
	if(gpgme_signers_add(slave_crypto_ctx.gpgme_context, slave_crypto_ctx.secret_key_OMN_slavePersonal) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to add slave's personal secret key as a signer!\n");
		exit(-1);
	}
	
	fprintf(stdout, "Successfully added slave's personal secret key as a signer\nNumber of keys used to sign: %d\n", 
			gpgme_signers_count(slave_crypto_ctx.gpgme_context));

	//ok we're ready to sign! Detached signature since we are going to send ONLY the signature (without cleartext!)
	if(gpgme_op_sign(slave_crypto_ctx.gpgme_context, cleartext_for_sig, tmp.sigA__tB_pKBRESP, GPGME_SIG_MODE_DETACH) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to sign Auth4 DATA!!!!\n");
		exit(-1);
	}

	//let's ripristinate (at the first byte) the pointer in the signature data_T object (right now is pointing at the last byte written!).
	gpgme_data_seek(tmp.sigA__tB_pKBRESP, 0, SEEK_SET);
	fprintf(stdout, "Successfully signed cleartext gpgme object!\n");

	//we can now free the buffer
	free(buf_pKB_RESP);
	gpgme_data_release(cleartext_for_sig);
	//TODO: remember to free the two other gpgme_data_t objects!
	//let's free the response too, we won't need it anymore!
	fprintf(stdout, "Successfully freed memory!\n");


	return tmp;	
}

//master for token.
Auth4 build_Auth4(Data_lockedon_master* master, Response rsp, SlaveCryptoCtx& slave_crypto_ctx) {
	Auth4 tmp;
	
	//we need a gpgme_data_t object to contain the cleartext just for the "RESP"/response part.
	gpgme_data_t cleartext_rsp;

	//empty cleartext_resp, will contain stringified rsp only.
	if(gpgme_data_new(&cleartext_rsp) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain cleartext response for Auth4 message!\n");
		exit(-1);
	}
	
	//we need two more gpgme_data_t objects: one to contain the encrypted response, the other to contain the signature from the Auth4 message.
	//empty gpgme_data_t that will contain signature!
	if(gpgme_data_new(&(tmp.sigA__tB_pKBRESP)) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain signature for Auth4 message!\n");
		exit(-1);
	}
	
	//empty gpgme_data_t that will contain the encrypted cleartext_rsp!
	if(gpgme_data_new(&(tmp.pKB_RESP)) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain encrypted payload for Auth4 message!\n");
		exit(-1);
	}

	//ok we got the empty objects.
	//We first need to "craft" the pKB_RESP part.
	size_t size_of_rsp_stringified;
	char* rsp_stringified = stringify_response(rsp, size_of_rsp_stringified);	
	if(gpgme_data_write(cleartext_rsp, rsp_stringified, size_of_rsp_stringified) == -1) {
		fprintf(stderr, "Failed to copy response inside cleartext data object, for Auth4 message!\n");
		exit(-1);
	} else {
		fprintf(stdout, "Successfully copied response (%ld bytes) inside cleartext data object, for Auth4 message!\n", size_of_rsp_stringified);
	}

	//oook, let's reset the cursor to point at the start of cleartext, otherwise we are going to sign 0 bytes of data!
	//(it signs starting from current pointer position)
	gpgme_data_seek(cleartext_rsp, 0, SEEK_SET);


	//now we need to encrypt the response, we don't want anyone, apart the master, to read it!	
	gpgme_key_t recipients_keys[2] = {slave_crypto_ctx.public_key_OMN_master, NULL};
	
	if(gpgme_op_encrypt(slave_crypto_ctx.gpgme_context, recipients_keys, 
				(gpgme_encrypt_flags_t) (GPGME_ENCRYPT_ALWAYS_TRUST, GPGME_ENCRYPT_NO_ENCRYPT_TO | GPGME_ENCRYPT_PREPARE),
				cleartext_rsp, tmp.pKB_RESP) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to encrypt payload with master's public key!\n");
		exit(-1);
	}

	fprintf(stdout, "Successfully encrypted cleartext gpgme object!\n");
	
	//let's get the size of the cyphertext!	
	size_t size_of_pKB_RESP = gpgme_data_seek(tmp.pKB_RESP, 0, SEEK_CUR);
	//let's reset the cursor to point at the start of the cyphertext.
	gpgme_data_seek(tmp.pKB_RESP, 0, SEEK_SET);

	//we'll "free" in "gpgme terms" the gpgme_data_t inside tmp later... The user must use it before!
	//we still need to free the cleartext tho...
	gpgme_data_release(cleartext_rsp);
	//let's free the memory used for the "stringified" version of response...
	free(rsp_stringified);

	//We just "crafted" the pKB_RESP part. We are now able to "craft" the signature as sigSLAVE(token|pKB_RESP)
	//first off, we need another gpgme_data_t object, to contain the "cleartext" of the signature.
	gpgme_data_t cleartext_for_sig;

	if(gpgme_data_new(&cleartext_for_sig) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain cleartext for Auth4 signature!\n");
		exit(-1);
	}

	//then we fill it as token|pKB_RESP	
	if(gpgme_data_write(cleartext_for_sig, &(master->his_token), sizeof(int)) == -1) {	
		fprintf(stderr, "Failed to copy token inside cleartext (to be signed) data object, for Auth4 signature!\n");
		exit(-1);
	} else {	
		fprintf(stdout, "Successfully copied token (%d) inside cleartext data object, for Auth4 signature!\n", master->his_token);
	}
	
	//to write pKB_RESP inside the cleartext we first need to read the contents of the gpgme_data_t object that we crafted before.
	char* buf_pKB_RESP = NULL;
	buf_pKB_RESP = (char *) malloc(size_of_pKB_RESP);
	if(buf_pKB_RESP == NULL) {
		fprintf(stderr, "Failed to allocate space to read the encrypted part of Auth4 cleartext for signature object.\n");
		exit(-1);
	}
	if(gpgme_data_read(tmp.pKB_RESP, buf_pKB_RESP, size_of_pKB_RESP) == -1) {	
		fprintf(stderr, "Failed to read encrypted response data object, for Auth4 signature!\n");
		exit(-1);
	}
	gpgme_data_seek(tmp.pKB_RESP, 0, SEEK_SET); //always ripristinate the cursor!
	//we can now finish the filling of cleartext_for_sig
	if(gpgme_data_write(cleartext_for_sig, buf_pKB_RESP, size_of_pKB_RESP) == -1) {	
		fprintf(stderr, "Failed to copy encrypted response inside cleartext (to be signed) data object, for Auth4 signature!\n");
		exit(-1);
	} else {	
		fprintf(stdout, "Successfully copied encrypted response (%ld bytes) inside cleartext data object, for Auth4 signature!\n", size_of_pKB_RESP);
	}
	gpgme_data_seek(cleartext_for_sig, 0, SEEK_SET); //always ripristinate the cursor!


	//let's sign!
	//now we need to add the secret key of OMN slave (personal) to the "signers" list.
	if(gpgme_signers_add(slave_crypto_ctx.gpgme_context, slave_crypto_ctx.secret_key_OMN_slavePersonal) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to add slave's personal secret key as a signer!\n");
		exit(-1);
	}
	
	fprintf(stdout, "Successfully added slave's personal secret key as a signer\nNumber of keys used to sign: %d\n", 
			gpgme_signers_count(slave_crypto_ctx.gpgme_context));

	//ok we're ready to sign! Detached signature since we are going to send ONLY the signature (without cleartext!)
	if(gpgme_op_sign(slave_crypto_ctx.gpgme_context, cleartext_for_sig, tmp.sigA__tB_pKBRESP, GPGME_SIG_MODE_DETACH) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to sign Auth4 DATA!!!!\n");
		exit(-1);
	}

	//let's ripristinate (at the first byte) the pointer in the signature data_T object (right now is pointing at the last byte written!).
	gpgme_data_seek(tmp.sigA__tB_pKBRESP, 0, SEEK_SET);
	fprintf(stdout, "Successfully signed cleartext gpgme object!\n");

	//we can now free the buffer
	free(buf_pKB_RESP);
	gpgme_data_release(cleartext_for_sig);
	//TODO: remember to free the two other gpgme_data_t objects!
	//let's free the response too, we won't need it anymore!
	fprintf(stdout, "Successfully freed memory!\n");


	return tmp;	
}

NormObjectHandle send_Auth4(NormSessionHandle session, Auth4& auth4, SlaveCryptoCtx& slave_crypto_ctx, char** msg) {

	//Ok! let's send the auth4 message. We will need to define a point of separation between the encrypted payload and the signed payload.
	//We'll do this just with a long at the start of the message, signifying the length of the encrypted payload.
	//The slaves and masters will need to sanitize it, since we'll send it in the clear.
	
	
	//1) Let's get the 2 gpgme_data_t object memory content.
	size_t length_of_cyphertext;
	char* cyphertext_to_be_sent = gpgme_data_release_and_get_mem(auth4.pKB_RESP, &length_of_cyphertext);

	if(cyphertext_to_be_sent == NULL) {
		fprintf(stderr, "Failed to release auth4's gpgme data_t cyphertext object!\n");
		exit(-1);
	}

	size_t length_of_signature;
	char* signature_to_be_sent = gpgme_data_release_and_get_mem(auth4.sigA__tB_pKBRESP, &length_of_signature);

	if(signature_to_be_sent == NULL) {
		fprintf(stderr, "Failed to release auth4's gpgme data_t signature object!\n");
		exit(-1);
	}

	//2) now we add the two lengths, and check for overflow. We need to account in the size_t for the length of cyphertext too!!
	size_t length_of_payload = 0;
	if(sizeof(size_t) == sizeof(unsigned long)) {
		size_t tmp = 0;
		if(__builtin_uaddl_overflow(length_of_signature, length_of_cyphertext, &tmp)) {
			fprintf(stderr, "Overflow occured when trying to create payload for auth4 message. Size of cyphertext: %ld. Size of signature: %ld.\n",
					length_of_cyphertext, length_of_signature);
			exit(-1);
		}
		
		if(__builtin_uaddl_overflow(tmp, sizeof(size_t), &length_of_payload)) {
			fprintf(stderr, "Overflow occured when trying to create payload for auth4 message. Size of cyphertext + signature: %ld. Size of size_t: %ld.\n",
					tmp, sizeof(size_t));
			exit(-1);
		}
	} else {
		fprintf(stderr, "Size_t is not of type long.\n");
		exit(-1);
	}
	

	//let's allocate memory for the payload.
	*msg = (char*) malloc(length_of_payload);

	if(*msg == NULL) {
		fprintf(stderr, "Failed to allocate memory for auth3's message payload. Required %ld bytes\n", length_of_payload);
		exit(-1);
	}


	memcpy(*msg, &length_of_cyphertext, sizeof(size_t)); //first the length of cyphertext
	memcpy(*msg + sizeof(size_t), cyphertext_to_be_sent, length_of_cyphertext); //then the cyphertext
	memcpy(*msg + sizeof(size_t) + length_of_cyphertext, signature_to_be_sent, length_of_signature); //lastly, the signature.

	//3) let's send the payload.
	NormObjectHandle auth4_sent = NormDataEnqueue(session, *msg, length_of_payload, NULL, 0);

	fprintf(stdout, "Sent Auth4 message! Total bytes: %ld\n", length_of_payload);
	fprintf(stdout, "message:\n%s\n", *msg);





	gpgme_free(signature_to_be_sent);
	gpgme_free(cyphertext_to_be_sent);


	return auth4_sent;

}


EpkMaster_RESP get_EpkMaster_RESP_from_auth4_msg(Auth4 auth4, NormNodeId local_slave_id) {
	EpkMaster_RESP tmp = {local_slave_id, false, NULL, 0};

	//Ok... copy all the encrypted gpgme buffer content..	
	gpgme_data_seek(auth4.pKB_RESP, 0, SEEK_SET);
	tmp.size = gpgme_data_seek(auth4.pKB_RESP, 0, SEEK_END);
	gpgme_data_seek(auth4.pKB_RESP, 0, SEEK_SET);
	
	tmp.ptr = (char*) malloc(tmp.size);

	if(tmp.ptr == NULL) {
		fprintf(stderr, "Failed to allocate memory for encrypted message. Required %ld bytes\n", tmp.size);
		exit(-1);
	}

	if(gpgme_data_read(auth4.pKB_RESP, tmp.ptr, tmp.size) == -1) {
		fprintf(stderr, "Failed to read encrypted response data object!\n");
		exit(-1);
	}


	gpgme_data_seek(auth4.pKB_RESP, 0, SEEK_SET);


	return tmp;	

}


//num of active slaves doesn't include the local node.
Command OMN_sendResult(NormInstanceHandle instance, NormSessionHandle session, SlaveCryptoCtx& slave_crypto_ctx, Data_lockedon_master* master,
		Execute_command_parms* thread_exeCmd_params, pthread_t* thread_exeCmd_id, Command command, std::vector<Data_slave>& otherSlaves,
		std::vector<EpkMaster_RESP>& v_RESPs) {

    long num_of_active_slaves_originally = otherSlaves.size();

    bool keepGoing = true;
    bool command_got_executed = false;
  
    //watchout, size type EXPLICIT conversion to INT.  
    bool are_we_waiting_for_more_responses = (std::min((int) otherSlaves.size(), slave_crypto_ctx.get_number_of_known_slaves())) > 0;
    

    fprintf(stdout, "OMN: Starting sending result phase...\nProcess will last indefinitely...\n");
    
    Auth4 to_be_sent;
    char* payload_auth4 = NULL;
    NormObjectHandle h_NORMOBJECT_auth4 = NORM_OBJECT_INVALID;
    bool last_TX_Auth4_purged = true;
    bool last_TX_Auth4_has_been_sent_at_least_1_time = false;


    //-----------------------------------------------//
    //we need this part for the Auth4 slave responses timeout! For efficiency we will use the select() even without a timeout!
    struct timeval startingTime;
    struct timeval timeout;
    
    int retval;
   

   ProtoSystemTime(startingTime); 

    //let's get norm descriptor in order to not block when we call NormGetNextEvent()
    NormDescriptor fd_NORM = NormGetDescriptor(instance);
    //-----------------------------------------------//

    //let's cycle the NORM events till we pick up an Auth4 message:
    while (keepGoing){
	//first off, we check every time if we can get a lock over the mutex, to access the memory shared with the "command" thread.
	if(!command_got_executed) {
		int tryloc_err = pthread_mutex_trylock(&mutex_execute_command);
		if(tryloc_err == 0) {
			//critical section
			if(thread_exeCmd_params->response_avaliable) {
				//this means SECONDARY thread has returned.
				//Response contains a valid response to be sent in an Auth4 message.
				fprintf(stdout, "SEND RESULT: command thread has returned, command has been executed!\n");
				//1) Join the thread. THE CALLS BLOCKS! AFTER THIS CALL, WE DON'T NEED TO TRY TO LOCK THE GPGME_MUTEX: THERE ARE NOT OTHER THREADS ANYMORE!
				pthread_join(*thread_exeCmd_id, NULL);
				//2) Set the boolean to not reenter in this if
				command_got_executed = true;
				//3) send the Auth4 message.
				if(thread_exeCmd_params->encryption_not_needed) //just for OMN, since we save the encrypted version of responses we don't need to re-encrypt them.
				{
					fprintf(stdout, "SEND RESULT: Response is ready to be sent (bypass encryption)!\n");
					to_be_sent = build_Auth4_bypass_encryption(master, thread_exeCmd_params->rsp, slave_crypto_ctx);

				} else {	
					fprintf(stdout, "SEND RESULT: Response is ready to be sent!\n");
					to_be_sent = build_Auth4(master, thread_exeCmd_params->rsp, slave_crypto_ctx);
				}
				
				EpkMaster_RESP tmp_ERESP = get_EpkMaster_RESP_from_auth4_msg(to_be_sent, slave_crypto_ctx.local_NORMid);
				v_RESPs.push_back(tmp_ERESP);

				h_NORMOBJECT_auth4 = send_Auth4(session, to_be_sent, slave_crypto_ctx, &payload_auth4);
				last_TX_Auth4_purged = false;

				//in any case, free the opt_data for the response!
				if(thread_exeCmd_params->rsp.len > 0) free(thread_exeCmd_params->rsp.opt_data);
			}

			pthread_mutex_unlock(&mutex_execute_command); //unlock in all cases.
			//end of critical section	
		} else {
			//commented out because of spam.
			//fprintf(stdout, "pthread seems locked: command thread has not returned, command has not been executed!\n");
		}
	
	}



    	//we need to use select() to check asyncronously if the norm thread has any events for us!
    	//We do this by telling select we want him to check if the NORM file descriptor
    	//is ready for a read (by adding him to the set of file descriptor we want to check
    	//for a "read ready" state), with a waiting timeout of 3 second!
    	
	//let's initialize the timeout struct for the select().
	//wait up to SELECT_TIMEOUT second to "select()" timeout.
    	timeout.tv_sec = SELECT_TIMEOUT;
   	timeout.tv_usec = 0;
	    
	//Now let's initialize the file descriptor read bucket!
	fd_set fdsetInput; 
	FD_ZERO(&fdsetInput); //we reset the bucket, everytime we want to check, cause the sets gets modified
       			      //in place to indicate which file descriptors are currently ready (manpage)
    	FD_SET(fd_NORM, &fdsetInput); //we add the NORM file descriptor to the set, cause we want to check him.
    
	//we don't want to check exceptional or write "ready" state for any fd, we leave those FD buckets as NULL.
	//we just want to check the input set!
	//the first one must be the highest file descriptor value in all buckets, plus 1...
	//ok... let's pass the timeout too and we ready to go! THIS CALL WILL NOT BLOCK!
	retval = select(fd_NORM+1, &fdsetInput, NULL, NULL, &timeout);


	//if retval is 1, that means fd_NORM has become ready for a read -> a NORM EVENT is waiting to be picked up!
	if(retval == -1) {
		fprintf(stdout, "SEND RESULT: select(): has returned an error\n"); //welp, can't do much!
	} else if(retval) { 

		NormEvent theEvent;
		
		//let's block till we get a NORM event!
		if (!NormGetNextEvent(instance, &theEvent)) continue; //if NORM doesn't return an event, it's not an error...
								      //just continue!
		
		switch (theEvent.type){
			case NORM_RX_OBJECT_COMPLETED: //oh... a new NORM object... Will it be a valid Auth4 message coming from another slave?
				{
					if(are_we_waiting_for_more_responses) {
						//We can receive two kinds of NORM objects:
						//Those that come from authenticated slave NORMIDs, and those that do not.
						//Whatever the case, they can be or not Auth4 messages.
						//We can use the NORMID just to "speed" things up.
						fprintf(stdout, "SEND RESULT: Received another message, possible new response (Auth4)!\n");
						char* crypted_rsp_buffer;
						size_t length_of_crypted_rsp_buffer;
						
						long index_of_sender = 0;
						if(find_data_slave(otherSlaves, NormNodeGetId(NormObjectGetSender(theEvent.object)), index_of_sender)) {
					
							//TODO: modify call to verify_auth4, changed protocol, v4
							//WE NEED TO LOCK THE GPGME_MUTEX!
							pthread_mutex_lock(&gpgme_crypto_ctx_mutex);
							///////////////////////////////////////////////////////
							//////////////////CRITICAL SECTION/////////////////////
							///////////////////////////////////////////////////////
							
							if(verify_Auth4(&theEvent, slave_crypto_ctx, otherSlaves[index_of_sender].token_for_him, &crypted_rsp_buffer, &length_of_crypted_rsp_buffer)){

								fprintf(stdout, "SEND RESULT: authed Auth4 received.\n");
								
								//the verification was a success, let's "consume" the token... can't use it anymore!
								otherSlaves.erase(otherSlaves.begin() + index_of_sender);
								//let's check if we got the same number of responses we can get based on the current number of known slaves (pubkeys), if it is, TRY TO break out of the loop (we must send one auth4)!

								
								//add the crypted_rsp_buffer to the v_RESPs vector...
								EpkMaster_RESP tmp_ERESP = {NormNodeGetId(NormObjectGetSender(theEvent.object)), true, crypted_rsp_buffer, length_of_crypted_rsp_buffer};
								
								v_RESPs.push_back(tmp_ERESP);
								//gpgme_free(crypted_rsp_buffer); //gotta free it! It once was a gpgme_data_t object!



							} else {
								fprintf(stdout, "SEND RESULT: Received another message, but it was not a valid Auth4!\n");
							}
							
							///////////////////////////////////////////////////////
							////////////////END OF CRITICAL SECTION////////////////
							///////////////////////////////////////////////////////
							pthread_mutex_unlock(&gpgme_crypto_ctx_mutex);
												
							

						} else {
							fprintf(stdout, "SEND RESULT: Received another message, but the sender's NORM id isn't inside the list of slaves for which we are awaiting a response!\n");
						}
					} else {
						fprintf(stdout, "SEND RESULT: Received another message, but there are no more active slaves! Can't be an auth4 response!\n");
					
					}
				} //end case NORM_RX_OBJECT_COMPLETED
				break;
			case NORM_TX_OBJECT_SENT:
				{
					if(theEvent.object == h_NORMOBJECT_auth4) {
						fprintf(stdout, "SEND RESULT: Auth4 NORM OBJECT sent at least 1 time!\n");
						last_TX_Auth4_has_been_sent_at_least_1_time = true;	
					} else {
						fprintf(stderr, "SEND RESULT: Some other NORM message was sent at least 1 time...\n");
					}
				}
				break;
			case NORM_REMOTE_SENDER_NEW:
				{
					fprintf(stdout, "SEND RESULT: New sender! Another master? Or a new slave perhaps... We don't mind\n");
				} //end case NORM_REMOTE_SENDER_NEW
				break;
			case NORM_TX_OBJECT_PURGED:
				//We can enter there only if we already sent an Auth4 response.
				//In this case, we need to free the payload of the Auth4.

				//NORM just purged our Auth2 from sending queue!!!!
				if(!last_TX_Auth4_purged && theEvent.object == h_NORMOBJECT_auth4) {
					fprintf(stdout, "SEND RESULT: Auth4 NORM OBJECT Purged!\n");
					free(payload_auth4);
					h_NORMOBJECT_auth4 = NORM_OBJECT_INVALID;
					last_TX_Auth4_purged = true;
				} else {
					fprintf(stderr, "SEND RESULT: Some other NORM message was purged...\n");
				}
				break;
			default:
				TRACE("SEND RESULT: Got event type: %d\n", theEvent.type); 
		}  // end switch(theEvent.type)



	} else { //we enter there if retval == 0, which means select() has timed out while waiting for 
		 //NORM file descriptor to become read-ready!
		fprintf(stdout, "SEND RESULT: just a heads up, select() has timed out! Don't worry too much!\n");
	}

	//did we pass the SENDRESULT_SLAVE_TIMEOUT seconds??? Let's check the clock now and compute how much time has passed
	//since we started the send result phase.
	//Normally a scan can take quite some time... a crash can occur so it is good practice to unlock slaves after quite some time.
	
	struct timeval currentTime;
	ProtoSystemTime(currentTime);
	if(otherSlaves.size() == (num_of_active_slaves_originally - slave_crypto_ctx.get_number_of_known_slaves())) are_we_waiting_for_more_responses = false;
	//we can enter here even if we don't need to wait anymore cause we are not waiting for more responses!
   	if((currentTime.tv_sec - startingTime.tv_sec > SENDRESULT_SLAVE_TIMEOUT) || !are_we_waiting_for_more_responses) {

	//WE CAN'T DROP A RESULT PHASE IF OUR SCAN DIDN'T COMPLETE YET!!!!!!!!!!! THING IS, PROBABLY THE SCAN IS STILL ONGOING ON OTHER SITES TOO!
	//JUST RESET TIMERS TO LET OMN CONTINUE WORKING ON IT FOR ANOTHER SENDRESULT_SLAVE_TIMEOUT PERIOD!
		if(command_got_executed) {

	//MOREOVER, WE CAN'T DROP THE RESULT PHASE IF WE DIDN'T SEND THE AUTH4 AT LEAST 1 TIME (this is to prevent damage in the scenario where
	//the scan finished just in time for the timeout, but the Auth4 message can't be sent becase of no time!)!
			if(last_TX_Auth4_has_been_sent_at_least_1_time) {
				//oh, we're inside here huh?
				//this means we got to end the cycle right here.
				keepGoing = false;
				//force purge the auth4 message, if it has 	
				if(!last_TX_Auth4_purged) {
					free(payload_auth4);
					NormObjectCancel(h_NORMOBJECT_auth4);
					h_NORMOBJECT_auth4 = NORM_OBJECT_INVALID;
					last_TX_Auth4_purged = true;
				}

				fprintf(stderr, "SEND RESULT: AUTH4>>>Slave timed out on waiting for Auth4  messages from other slaves. Forcing termination of send result phase!\n");
			} else {
				//let's just add some time...
				startingTime.tv_sec += GRACE_TIME;
			}
		} else {
    			ProtoSystemTime(startingTime);
		}
	};



    } //end while

    if(!last_TX_Auth4_purged) {
	    NormObjectCancel(h_NORMOBJECT_auth4);
	    h_NORMOBJECT_auth4 = NORM_OBJECT_INVALID;
	    free(payload_auth4);
	    last_TX_Auth4_purged = true;
    }


    fprintf(stdout, "Send result phase ended. We got %ld/%ld responses\n", num_of_active_slaves_originally - otherSlaves.size(), num_of_active_slaves_originally);
}








/**
 *	Function used to verify received data, in order to establish if it is a valid Auth4 message.
 *	IT DOES INDEED CHECK IF THE SENDER IS A VALID SLAVE (E.g. the signature contained in it is valid).
 *	Generally, if it returns true the client will proceed to save the response contained in it, but only if the command was of type "SCAN",
 *	
 *
 *	\param event The NORM event, used to get the data.
 *	\param token_to_verify the token pertinent to the data inside event. It is the token associated with the sender of the object inside event.
 *	\param response Will contain the received response, if "save" is true and if the data in NORM event is a valid and authenticated Auth4 message.
 *	\param length_of_response Will contain response's length in bytes.
 *	\param save If it is true, response will contain a pointer to a gpgme_data_t object containing the response encrypted with master's public Key.
 *
 *	\return true if data in NORM event is a valid Auth4 message, false otherwise. 
 */
bool verify_Auth4(NormEvent* event, SlaveCryptoCtx& slave_crypto_ctx, int token_to_verify, char** response, size_t* length_of_response) {


	/***************************************************************************************************************************/
	/*************************************************CHECKING GOOD FORMAT******************************************************/
	/***************************************************************************************************************************/


	bool is_auth4_valid = false; //can only change to true if the sanitizing and verification of encrypted result doesn't fail for Auth4.

	NormObjectHandle obj = event->object;
	//1) object type MUST be NORM_OBJECT_DATA
	if(NormObjectGetType(obj) != NORM_OBJECT_DATA) {
		fprintf(stderr, "Message isn't an Auth4 slave response. NormObject was not NORM_OBJECT_DATA.\n");
		return false;
	}
	
	//We can't say anything certain about the max size of an Auth4 response... It varies since signature and encryption is armored (base64) and since
	//the encrypted original payload is compressed and can contain files or lists of files.
	//Let's just not process any Auth4 message longer than 2MB, which really overkill, even for a NMAP scan results file.
	//But still, it's just a max to set a limit on the amount of data we try to decrypt and verify with GPG.
	if(NormObjectGetSize(obj) >= (2*1024*1024)) {
		fprintf(stderr, "Message isn't an Auth4 slave response. NormObject was not shorter than 2MB\n");
		return false;	
	}
	
	//We can say something about the minimum size of an Auth4 response: 
	//It must at least contain sizeof(size_t) bytes; the first sizeof(size_t) bytes represent the length of the cyphertext that follows them.
	//It must contain then 566 bytes; Generally a detached UNARMORED signature is 566 bytes long. This is the BARE minimum.
	//   OMN sends only ARMORED signatures, but we can use this information to create a lower boundary for the size of a valid Auth3 message.
	if(NormObjectGetSize(obj) < (sizeof(size_t) + 566)) {
		fprintf(stderr, "Message isn't an Auth4 slave response. NormObject was not longer than %ld bytes\n", sizeof(size_t)+566);
		return false;
	}

	fprintf(stdout, "Message contained a correcly formatted Auth4 message...\n");
	//Can't verify much more without taking some data...
	
	//Let's generate a valid Auth4 struct
	const char* data = NormDataAccessData(obj);
	
	//1)let's get the length of cyphertext:
	//	We must sanitize it before using it in the program, it must be:
	//	a) > 0
	//	b) sizeof(size_t) + length_of_cyphertext < NormObjectGetSize(obj) -> the last byte of the encrypted result must be contained inside the buffer:
	//									     can't read beyond boundaries of NormObject data!
	//	c) NormObjectGetSize(obj) - (sizeof(size_t) + length_of_cyphertext) >= 566 --> There should be enough space for an unarmed signature after it.
	size_t length_of_cyphertext = 0;
	memcpy((void *) &length_of_cyphertext, (void *) data, sizeof(size_t));
	//a
	if(length_of_cyphertext <= 0) {	
		fprintf(stderr, "ERROR during auth4 sanitizing! Cyphertext length %ld is not valid:  must be positive!\n", length_of_cyphertext);
		return false;
	}
	//b
	size_t tmp_sum = 0;
	if(__builtin_uaddl_overflow(sizeof(size_t), length_of_cyphertext, &tmp_sum)) {
		fprintf(stderr, "Overflow occured when trying to sanitize Auth4 messsage. Size of cyphertext: %ld. Size of length:%ld.\n",
				length_of_cyphertext, sizeof(size_t));
		return false;
	}
	if(tmp_sum >= NormObjectGetSize(obj)) {	
		fprintf(stderr, "ERROR during auth4 sanitizing! Cyphertext length %ld suggests a possible read out of boundaries, ABORTING!\n", length_of_cyphertext);
		return false;
	}
	//c
	size_t size_of_possible_signature = 0;
	if(__builtin_usubl_overflow(NormObjectGetSize(obj), tmp_sum, &size_of_possible_signature)) {
		fprintf(stderr, "Overflow occured when trying to sanitize Auth4 messsage. Size of cyphertext + length: %ld. Size of NORM object:%ld.\n",
				tmp_sum, NormObjectGetSize(obj));
		return false;
	}
	if(size_of_possible_signature < 566) {
		fprintf(stderr, "ERROR during auth4 sanitizing! Size of possible signature is shorter than the minimum size of %d bytes! IMPOSSIBLE!\n", 566);
		return false;
	}

	//OK, seems like the length of cyphertext is a valid message. Let's copy all the data inside the two data_t objects.
	Auth4 received_auth4;


	//empty gpgme_data_t that will contain signature!
	if(gpgme_data_new(&(received_auth4.sigA__tB_pKBRESP)) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain signature from Auth4 message!\n");
		exit(-1);
	}
	//let's fill it up with the real signature (the remaining part of the data: full data minus the first part, size_of(size_t) + length_of_cyphertext)!
	if(gpgme_data_write(received_auth4.sigA__tB_pKBRESP, (void*) &(data[0 + sizeof(size_t) + length_of_cyphertext]), size_of_possible_signature) == -1) {
		fprintf(stderr, "Failed to copy received Auth4 signature part inside signature data object!\n");
		exit(-1);
	}
	fprintf(stdout, "Successfully wrote and prepared Auth4 signature data (received bytes: %ld), to be verified by OMN slave...\nSignature is long %ld bytes...\n", NormObjectGetSize(obj), gpgme_data_seek(received_auth4.sigA__tB_pKBRESP, 0, SEEK_CUR));
	//oook, let's reset the cursor to point at the start of the signature object, otherwise we are going to verify 0 bytes of data!
	//(it signs starting from current pointer position)
	gpgme_data_seek(received_auth4.sigA__tB_pKBRESP, 0, SEEK_SET);



	//empty gpgme_data_t that will contain encrypted payload!
	if(gpgme_data_new(&(received_auth4.pKB_RESP)) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain cyphertext from Auth4 message!\n");
		exit(-1);
	}
	//let's fill it up with the real cyphertext (the first bytes of the data, minus the size_t field)!
	if(gpgme_data_write(received_auth4.pKB_RESP, (void*) &(data[0 + sizeof(size_t)]), length_of_cyphertext) == -1) {
		fprintf(stderr, "Failed to copy received Auth4 cyphertext part inside cyphertext data object!\n");
		exit(-1);
	}
	fprintf(stdout, "Successfully wrote and prepared Auth4 cyphertext data (received bytes: %ld)...\nCyphertext is long %ld bytes...\n", NormObjectGetSize(obj), gpgme_data_seek(received_auth4.pKB_RESP, 0, SEEK_CUR));
	//oook, let's reset the cursor to point at the start of the cyphertext object
	gpgme_data_seek(received_auth4.pKB_RESP, 0, SEEK_SET);

	/***************************************************************************************************************************/
	/***************************************************VERIFICATION PHASE******************************************************/
	/***************************************************************************************************************************/
	
	//We need to:
	//1) rebuild the old "cleartext" for the signature, by appending to the left the token.
	//2) verify the cleartext using the signature.

	//1)...
	gpgme_data_t cleartext;
	
	//create a new empty object for this purpose!
	if(gpgme_data_new(&cleartext) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain cleartext from Auth4 message!\n");
		exit(-1);
	}

	//first, fill it up with the token
	if(gpgme_data_write(cleartext, &(token_to_verify), sizeof(int)) == -1) {	
		fprintf(stderr, "Failed to copy token inside cleartext (to be verified) data object, for Auth4 signature!\n");
		exit(-1);
	} else {	
		fprintf(stdout, "Successfully copied token (%d) inside cleartext data object, for Auth4 signature verification!\n", token_to_verify);
	}
	
	//then finish filling it up with the encrypted response (pKB_RESP)
	//to write pKB_RESP inside the cleartext we first need to read the contents of the gpgme_data_t object that we crafted before.
	char* buf_pKB_RESP = NULL;
	buf_pKB_RESP = (char *) malloc(length_of_cyphertext);
	if(buf_pKB_RESP == NULL) {
		fprintf(stderr, "Failed to allocate space to read the encrypted part of Auth4, in order to verify it.\n");
		exit(-1);
	}
	if(gpgme_data_read(received_auth4.pKB_RESP, buf_pKB_RESP, length_of_cyphertext) == -1) {	
		fprintf(stderr, "Failed to read encrypted response data object, in order to verify Auth4 signature!\n");
		exit(-1);
	}
	gpgme_data_seek(received_auth4.pKB_RESP, 0, SEEK_SET); //always ripristinate the cursor!
	//we can now finish the filling of cleartext
	if(gpgme_data_write(cleartext, buf_pKB_RESP, length_of_cyphertext) == -1) {	
		fprintf(stderr, "Failed to copy encrypted response inside cleartext (to be verified) data object, for Auth4 signature!\n");
		exit(-1);
	} else {	
		fprintf(stdout, "Successfully copied encrypted response (%ld bytes) inside cleartext data object, in order to verify Auth4 signature!\n", length_of_cyphertext);
	}
	gpgme_data_seek(cleartext, 0, SEEK_SET); //always ripristinate the cursor!

	bool is_signaturevalid = false;
	
	//Verify it!
	if(gpgme_op_verify(slave_crypto_ctx.gpgme_context, received_auth4.sigA__tB_pKBRESP, cleartext, NULL) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to complete verification of the Auth4 signature!\n");
		is_auth4_valid = false;	
	}


	gpgme_verify_result_t verification_results = gpgme_op_verify_result(slave_crypto_ctx.gpgme_context);

	if(verification_results == NULL) {
		fprintf(stderr, "Failed to get verify results!\n");
		is_auth4_valid = false;
	}


	//now we must check this message was signed with the right key, AND ONLY WITH THAT KEY! WE CAN'T LET OTHERS SIGN IT!
	gpgme_signature_t possible_signature = verification_results->signatures;

	if(possible_signature == NULL) fprintf(stderr, "Failed to recognize at least 1 signature!\n");
	else {
		is_signaturevalid = true;
		if(possible_signature->next != NULL){
		       	fprintf(stderr, "The message was signed by more than 1 key, OMN SIGNES ONLY WITH 1 KEY AT TIME!\n");
			is_signaturevalid = false;
		}
		
		if(!(possible_signature->summary & GPGME_SIGSUM_VALID)){
		   	fprintf(stderr, "Signature is invalid! GPGME_SIGSUM_GREEN:%d - GPGME_SIGSUM_RED: %d - GPGME_SIGSUM_SYS_ERROR: %d - GPGME_SIGSUM_KEY_MISSING: %d\n",
					(possible_signature->summary & GPGME_SIGSUM_GREEN),
					(possible_signature->summary & GPGME_SIGSUM_RED),
					(possible_signature->summary & GPGME_SIGSUM_SYS_ERROR),
			   		(possible_signature->summary & GPGME_SIGSUM_KEY_MISSING)
			       );
			if(possible_signature->summary == 0x0) {
				//Undocumented: github.com/comotion/cpm/issues/27
				fprintf(stderr, "----------------------------------------------------\n");
				fprintf(stderr, "IMPORTANT!!!!!Are you sure you trusted the OMN keys?\n");
				fprintf(stderr, "----------------------------------------------------\n");
			
			}

			is_signaturevalid = false;
		}

               //OK signature seems made by one of our keys in our keyring...
                //is it one of known slave's personal keys? IT MUST BE!
                std::string tmp_possible_signature_fpr = std::string(possible_signature->fpr);

                if(!slave_crypto_ctx.is_fingerprint_known(tmp_possible_signature_fpr)) {
                        fprintf(stderr, "Signature was NOT made with one of the known slaves' personal key!\n");
                        is_signaturevalid = false;
                } else if(NormNodeGetId(NormObjectGetSender(event->object)) != slave_crypto_ctx.m_gpgKeyFingerprint_slaveNORMid[tmp_possible_signature_fpr]) {
                                //the sender's NORM id MUST BE the same as the one of the fingerprint (so the same as the one specified in the primary UID of the key with fingerprint "tmp_possible_signature_fpr")
                                fprintf(stderr, "Signature was made with one of the known slaves' personal key, BUT THE SENDER NORMID IS NOT THE SAME AS THE ONE SPECIFIED IN THE SIGN KEY!!!! POSSIBLE REPLY ATTACK!!!\n");
                                is_signaturevalid = false;
                } else {
                        //"""it MUST NOT be one of the signature already seen. If we see again a fingerprint, then it is a replayed signature and someone is trying to auth his NORMID!!!"""
                        /* No need for this check. The token is unique and can be used to auth only one valid response.
                         * After a response is authed, the token is automatically deleted. Thus, we can't use it to auth a replayed message, cause the token doesn't exist anymore!
                         * Even if an attacker were to try to use the signature of the replayed message, the attack would fail for 2 reasons:
                         *      1) in "nodesFound" there is no more the association NodeID->token required to auth the replayed message.
                         *         this means "find_data_slave" fails.
                         *      2) IF the attacker were to use its own NORM id, we got two cases:
                         *              a) the NORM id is still contained in "nodesFound": the attack will fail because we expect a signature made from another key in respect to that of the replayed message (even if the tokens are the same, so we pass all the previous controls except the previous elseif!).
                         *              b) the NORM id is not contained in "nodesFound": the attack will fail because there is no "nodeID->token" association (find_data_slave) fails.
                         *                 NOTE: This is the case for a replayed message coming from a "right" NORMid but whose token has been already consumed --> the NORM id is not (anymore) contained in "nodesFound"
                         *
                        for(Data_slave d: nodes_already_authed) {
                                if(std::string(d.his_fpr) == tmp_possible_signature_fpr) {
                                        fprintf(stderr, "Signature was made with one of the already-seen and known slaves' personal key! POSSIBLE REPLY ATTACK!!!\n");
                                        is_signaturevalid = false;
                                        break;
                                }
                        }
                        */
                }

		
		fprintf(stdout, "Signature was made with key with fingerprint %s\n", possible_signature->fpr);

		if(is_signaturevalid) fprintf(stdout, "SIGNATURE IS VALID!!!\n");
	}
	
	is_auth4_valid = is_signaturevalid;

	if(is_auth4_valid) {
		//if the encrypted payload is valid and the programmer wants to save the encrypted payload (I.E. the command was "SCAN")
		//we need to release the gpgme_data_t in a way to obtain the memory associated to it.
		*response = gpgme_data_release_and_get_mem(received_auth4.pKB_RESP, length_of_response);
	}

	/***************************************************************************************************************************/
	//we need to release all gpgme objects!
	free(buf_pKB_RESP);
	gpgme_data_release(cleartext);
	gpgme_data_release(received_auth4.sigA__tB_pKBRESP);


	return is_auth4_valid;


}



/*-----------------------------------------------------------------------------------------------------------*/

