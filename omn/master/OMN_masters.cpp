#include "OMN_masters.h"



string ncurses_selection_dialog(vector<string>& s) {
	
	initscr();

	cbreak(); //no need for "enter" button press.
	noecho(); //no echo for input
	keypad(stdscr, TRUE);
	curs_set(0); //non visible cursor.

	//get the maximum number of rows in the screen.
	//get the maximum number of characters we can print in the screen (horizontally)
	int rows = 0, columns = 0;
	int avaliable_rows = 0;

	int current_index_s = 0; //we start by printing the string at this index!
				 //if we got more strings than the screen can hold, when the user goes down
				 //with the arrows, we increment this index.
	int selected_string_on_screen = 0;

	bool selected = false; //when the user presses "ENTER", we return the selected string.
	int selected_string_index = 0;
	
	//fancy up and down arrow printing... search for the longest string.
	int longest_string = 1;
	for(string str: s) {
		longest_string = longest_string < str.length() ? str.length() : longest_string;
	}


	while(!selected) {
		getmaxyx(stdscr, rows, columns);
		//PRINTING PHASE...
		//we can only print max "columns" characters and max "rows" strings of "s".
		//and we can't print more strings than there are avaliable in "s".
		clear();
		
		avaliable_rows = rows - 3;
		if(avaliable_rows > 0) {
			mvprintw(0, 0, "Use up and down arrows to scroll, press enter to select.");
			
			//if more strings await "on the roof", print a string of '^'.
			if(current_index_s > 0) {
				for(int i=0; i< (columns < longest_string ? columns : longest_string); i++) mvprintw(1 , i, "^");
			}

			for(int i = 0; i<avaliable_rows && (i + current_index_s < s.size()); i++) { //ok cycle all available rows...
						
				//if the string is too big, print the first columns-3 characters, and the last ones are "..."
				string to_be_printed;
				
				if(s[i + current_index_s].length() > columns) {
					char temp[RESULT_NAME_LENGTH] = ""; 
					s[i + current_index_s].copy(temp, columns - 3);	
					to_be_printed = string(temp) + string("...");
				} else {
					to_be_printed = s[i+current_index_s];
				}

				//highlight only if selected
				if(i == selected_string_on_screen) {
					//A_STANDOUT is the best highlighting mode of the terminal.
					selected_string_index = i + current_index_s;
					wattron(stdscr, A_STANDOUT);
				} else {
					wattroff(stdscr, A_STANDOUT);
				}

				//print on screen.
				mvprintw(i + 2, 0, "%s", to_be_printed.c_str());
				
				wattroff(stdscr, A_STANDOUT);
			}
		
			//if more strings await "below", print a string of 'v'.
			if(current_index_s + avaliable_rows < s.size()) {
				for(int i=0; i<(columns < longest_string ? columns : longest_string); i++) mvprintw(rows - 1, i, "v");
			}
		
		} else {
			mvprintw(0, 0, "Window's too little!!!!!!");
		}

		refresh();

		//GET INPUT PHASE...
		int ch = 0;
		bool input_took = false;
		while(!input_took) {
			
			ch = getch();

			switch(ch) {
				case KEY_UP:
					{
						//move up only if we can
						int wanna_go_to = selected_string_on_screen - 1;

						if(wanna_go_to < 0)  {
							//check if we have other strings avaliable "on the rooftop"
							if(current_index_s > 0) {
								//we got more strings! WE CAN GO UP!
								//selected_string_on_screen stays the same (visually, we are already on the top)
								current_index_s--;
							} else {
								//NO MORE STRINGS! We stay right where we are.
							}
						} else {
							selected_string_on_screen = wanna_go_to;
						}
						input_took = true;
					}
					break;
				case KEY_DOWN:
					{
						//move down only if we can
						int wanna_go_to = selected_string_on_screen + 1;
						
						if(wanna_go_to >= avaliable_rows) {
							//check if we have other strings avaliable "under the screen"
							if(current_index_s + avaliable_rows < s.size() ) {
								//we got more strings! WE CAN GO DOWN!
								//selected_string_on_screen stays the same (visually, we are already on the lowest position)
								current_index_s++;
							}	
						} else {
							//ok... we didn't reach the rows, but maybe there are less strings in "s" than "rows" in the screen!!!
							if(wanna_go_to >= s.size()) {
								//can't go there!
							} else {
								selected_string_on_screen = wanna_go_to;
							}
						}
						input_took = true;
					}
					break;
				case '\n':
					{
						//this is the selected string. exit.
						selected = true;
						input_took = true;
					}
					break;
			}



		}	


	}

	endwin();

	return s[selected_string_index];
}


void launch_OMN_command(Command cmd, OMN_db_status master_db_status, MasterCryptoCtx master_crypto_ops_ctx, const char result_name[RESULT_NAME_LENGTH], const char* accept_only_this_result_hash) {
	bool set_tx_rate = false;
	double rate = 0;
	bool enable_message_trace = false;
	std::vector<Data_slave> nodesOMN; 

	// 1) Create a NORM API "NormInstance"
	NormInstanceHandle instance = NormCreateInstance();

	// 2) Create a NormSession using a generated local_id
	NormSessionHandle session = OMNCreateSession(instance, master_crypto_ops_ctx.local_NORMid);

	// 3) Set transmission rate
	if(set_tx_rate)
		NormSetTxRate(session, rate);  // in bits/second

	//setting transmission port (feedback, sender's messages, etc.)
	//as the adiacent UDP port. 
	NormSetTxPort(session, OMN_UDP_PORT + 1); 

	// enabling TCP-friendly congestion control
	NormSetCongestionControl(session, true);

	// NOTE: These are some debugging routines available 
	//       (not necessary for normal app use)
	// (Need to include "common/protoDebug.h" for this
	//SetDebugLevel(2);
	// Uncomment to turn on debug NORM message tracing
	if(enable_message_trace)
		NormSetMessageTrace(session, true);


	//we need both roles (receiver and sender) for AUTH protocol. 
	// 4) Start the sender using 
	//    	a random "sessionId"
	// 	  	1MB buffer space
	// 	  	1400B maximum payload size
	NormStartSender(session, generate_session_id(), 1024*1024, 1400, 64, 16);
	// 4.a) Start the receiver using
	// 	    1MB buffer space  PER Active NormSender! 
	NormStartReceiver(session, 1024*1024);


	// 5) DISCOVERY PHASE
	OMN_discovery(instance, session, master_crypto_ops_ctx, nodesOMN);
	fprintf(stdout, "-----------------------------------\n");
	fprintf(stdout, "-----------------------------------\n");
	fprintf(stdout, "-----------------------------------\n");
	fprintf(stdout, "Found %ld nodes.\n", nodesOMN.size());
	fprintf(stdout, "n)\tid\tchallenge\n");
	for(unsigned long i = 0; i < nodesOMN.size(); i++) {
		fprintf(stdout, "%ld)\t%d\t%d\n", i, nodesOMN[i].his_NORMID, nodesOMN[i].challengeReceivedFromHim);
	}
	fprintf(stdout, "-----------------------------------\n");
	fprintf(stdout, "-----------------------------------\n");
	fprintf(stdout, "-----------------------------------\n");

	//"send command and receive resuts" if we have at least 1 slave active in the session.
	if(nodesOMN.size() >= 1) {
	    // 6) SEND COMMAND PHASE
	    char* auth3_payload_to_be_freed = NULL;
	    int generated_token_for_command = -1;
		
	    
	    NormObjectHandle h_auth3NORM = OMN_sendCommand(instance, session, master_crypto_ops_ctx, nodesOMN, &auth3_payload_to_be_freed, cmd);

	    // 7) RECEIVE RESULTS PHASE
	    std::vector<wrapper_response> responses; //list of active nodes' responses!

	    //if the command was for removing one slave, we do not need to wait for him.
	    bool should_not_wait_for_deactivating_node = false;
	    if(cmd.codename == DELETE_SLAVE_PUBKEY) {
		should_not_wait_for_deactivating_node = true;
	    }

	    OMN_receiveResults(instance, session, master_crypto_ops_ctx, nodesOMN, responses, h_auth3NORM, &auth3_payload_to_be_freed, result_name, should_not_wait_for_deactivating_node);

	    //8) PROCESS RESULTS PHASE
	    process_results(responses, result_name, accept_only_this_result_hash, master_db_status);

	    if(cmd.len > 0)
		    free(cmd.opt_data);

	    //No need for sender role anymore...
	    NormStopSender(session);
	    //let's receive!


	} else {
		fprintf(stdout, "No OMN slaves found in session! Quitting without sending command!\n");
	}



	// 8) END!
	printf("Stopping receiver...\n");
	NormStopReceiver(session);
	if(nodesOMN.size() <= 1) NormStopSender(session); //just in case we couldn't enter the "send command and receive results" if!


	NormDestroySession(session);
	NormDestroyInstance(instance);

	fprintf(stdout, "OMN command execution: done.\n");
}


longopts_OMN parse_argv(int argc, char** argv, char** option_argument) {	


	int c;
	int digit_optind = 0;
	longopts_OMN longopt_of_user = INVALID_OPTION;

	//optind --> index of next element to be processed in argv
	int option_index = 0;
	static struct option long_options[] = {
	   {"scan", required_argument, (int*) &longopt_of_user, SCAN},
	   {"import-slave-pubkey", required_argument, (int*) &longopt_of_user, IMPORT_A_SLAVE_PUBKEY },
	   {"update",  no_argument,       (int*) &longopt_of_user,  UPDATE },
	   {"distribute-slave-pubkeys",  no_argument, (int*) &longopt_of_user,  DISTRIBUTE_SLAVE_PUBKEYS },
	   {"get",  no_argument, (int*) &longopt_of_user, GET },
	   {"active-slaves", no_argument, (int*) &longopt_of_user,  ACTIVE_SLAVES },
	   {"known-slaves",  no_argument, (int*) &longopt_of_user,  KNOWN_SLAVES },
	   {"print-master-info",  no_argument, (int*) &longopt_of_user,  KNOWN_SLAVES },
	   {"remove-slave", no_argument, (int*) &longopt_of_user, REMOVE_A_SLAVE},
	   {"help", no_argument, (int*) &longopt_of_user, HELP},
	   {0,         0,                 0,  0 }
	};

	//c = ... --> pick the character of the CURRENT argument.
	c = getopt_long(argc, argv, "s:i:ugrakhdp",
		long_options, &option_index);
	//no options? ERROR! Then break.
	if (c == -1) {
	   fprintf(stderr, "See the output of %s -h for a summary of options.\n", argv[0]);
	   exit(EXIT_FAILURE);
	}

	switch (c) {
	case 0: //long options...
	   fprintf(stdout, "option %s", long_options[option_index].name);
	   if (optarg) {
	       fprintf(stdout, " with arg %s\n", optarg);
	       *option_argument = optarg;
	   }
	   fprintf(stdout, "\n");
	   break;

	case 's':
	   fprintf(stdout, "option s with value '%s'\n", optarg);
	   longopt_of_user = SCAN;
	   *option_argument = optarg;
	   break;


	case 'i':
	   fprintf(stdout,"option i with value '%s'\n", optarg);
	   *option_argument = optarg;
	   longopt_of_user = IMPORT_A_SLAVE_PUBKEY;
	   break;
	
	case 'g':
	   fprintf(stdout, "option g\n");
	   longopt_of_user = GET;
	   break;

	case 'u':
	   longopt_of_user = UPDATE;
	   fprintf(stdout, "option u\n");
	   break;
	
	case 'd':
	   longopt_of_user = DISTRIBUTE_SLAVE_PUBKEYS;
	   fprintf(stdout, "option d\n");
	   break;

	case 'a':
	   longopt_of_user = ACTIVE_SLAVES;
	   fprintf(stdout, "option a\n");
	   break;

	case 'k':
	   longopt_of_user = KNOWN_SLAVES;
	   fprintf(stdout, "option k\n");
	   break;
	
	case 'p':
	   longopt_of_user = PRINT_MASTER_INFO;
	   fprintf(stdout, "option p\n");
	   break;

	case 'r':
	   longopt_of_user = REMOVE_A_SLAVE;
	   fprintf(stdout, "option r\n");
	   break;
	
	case 'h':
	   longopt_of_user = HELP;
	   fprintf(stdout, "option h\n");
	   break;

	case '?':
	   fprintf(stderr, "See the output of %s -h for a summary of options.\n", argv[0]);
	   exit(EXIT_FAILURE);
	   break;

	default:
	   fprintf(stderr, "?? getopt returned character code 0%o ??\n", c);
	}
	//}


	//if there are more NON-ARG arguments, print em off.
	if (optind < argc) {
	fprintf(stderr, "Ignoring other options... ");
	while (optind < argc)
	   fprintf(stderr, "%s ", argv[optind++]);
	fprintf(stderr, "\n");
	}

	
	return longopt_of_user;

}

bool MasterCryptoCtx::remove_slave_pubkey(char* slave_pubkey_fpr, int& num_of_keys_deleted) {

	int num_of_keys_currently_deleted = 0;

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

bool MasterCryptoCtx::rebuild_config_file() {
	
		
	
	std::string omn_filepath = std::string(getenv("HOME")) + "/" + std::string(OMN_DIRECTORY);
	
	struct stat st = {0};
	if(stat(omn_filepath.c_str(), &st) == -1) {
		mkdir(omn_filepath.c_str(), 0775);
	}
	
	std::string complete_filepath = omn_filepath + "/" + std::string(OMN_CFG_FILENAME);
	FILE* fp = fopen(complete_filepath.c_str(), "w");


	if(fp == NULL) fprintf(stderr, "Failed to open config file!\n");
	else {
		
		fprintf(fp, "master:%s\nslave_group:%s\nlan_name:%s\nNORM_ID:%u\n", public_key_OMN_master->fpr, public_key_OMN_slaveGroup->fpr, local_LAN_name.c_str(), local_NORMid);
		
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

void MasterCryptoCtx::print_master_info() {
	fprintf(stdout, "Master NORM id: %d\n", local_NORMid);
	fprintf(stdout, "Master pubkey GPG fingerprint: %s\n", public_key_OMN_master->fpr);	
	fprintf(stdout, "Master seckey GPG fingerprint: %s\n", secret_key_OMN_master->fpr);
	
	std::string omn_filepath = std::string(getenv("HOME")) + "/" + std::string(OMN_DIRECTORY);
	fprintf(stdout, "Master OMN folder path: %s\n", omn_filepath.c_str());

}

void MasterCryptoCtx::print_slaves_info() {


	fprintf(stdout, "Slave GROUP pubkey GPG fingerprint: %s\n", public_key_OMN_slaveGroup->fpr);
	
	for(auto& slv: m_gpgKeyFingerprint_slaveNORMid) {
		fprintf(stdout, "---------------------------------\n");	
		fprintf(stdout, "Slave LAN: %s\n", m_slaveNORMid_slaveLanName[slv.second].c_str());
		fprintf(stdout, "Slave NORM id: %u\n", slv.second);
		fprintf(stdout, "Slave pubkey GPG fingerprint: %s\n", slv.first.c_str());
		fprintf(stdout, "---------------------------------\n");	
	}
}

//called after gpgme_init(), works only for masters (cause it can get the master's secret key!)
//It initializes gpgme master's context, retrieving master's keypair and the slave's pubkey.
void MasterCryptoCtx::init_crypto_context() {


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
	char lan_name[LAN_NAME_LENGTH] = {0};
	

	std::string omn_filepath = std::string(getenv("HOME")) + "/" + std::string(OMN_DIRECTORY);
	std::string complete_filepath = omn_filepath + "/" + std::string(OMN_CFG_FILENAME);
	FILE* fp = fopen(complete_filepath.c_str(), "r");
	if(fp == NULL) {
		fprintf(stderr, "Failed to open config file!\n");
		exit(-1); //can't continue without keys!
	} else {
		NormNodeId NORM_nodeid_for_this_node;

		
		fscanf(fp, "master:%40s\nslave_group:%40s\nlan_name:%127s\nNORM_ID:%u\n", master_key_fpr, slaveGroup_key_fpr, lan_name, &NORM_nodeid_for_this_node);
		
		fprintf(stdout, "Here is the NORM ID of the master: %u\n", NORM_nodeid_for_this_node);
		fprintf(stdout, "Here is the fingerprint of the master keypair: %s\n", master_key_fpr);
		fprintf(stdout, "Here is the fingerprint of the slaves (group) keypair: %s\n", slaveGroup_key_fpr);
	
		this->local_NORMid = NORM_nodeid_for_this_node;
		this->local_LAN_name = string(lan_name);

		fprintf(stdout, "Getting slave personal key's fingerprints...\n");
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
	
	//now let's get the key, secret = 0 so we take only the PUBLIC key.	
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

	//let's get the secret key too (1)...
	if(gpgme_get_key(this->gpgme_context, master_key_fpr, &(this->secret_key_OMN_master), 1) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to load master secret key with fingerprint %s!\n", master_key_fpr);
		exit(-1);
	} else {
		if(this->secret_key_OMN_master == NULL) {
			
			fprintf(stderr, "SECRET KEY FOR OMN MASTER NOT FOUND. Searched fingerprint: %s\n", master_key_fpr);
			//should we delete it?
			exit(-1);
		}

	}

	//and slaves group's public key too!
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
	

	fprintf(stdout, "Key loaded! Fingerprint %s --- Is secret? %d\n", this->public_key_OMN_slaveGroup->fpr, this->public_key_OMN_slaveGroup->secret);
	fprintf(stdout, "Key loaded! Fingerprint %s --- Is secret? %d\n", this->secret_key_OMN_master->fpr, this->secret_key_OMN_master->secret);
	fprintf(stdout, "Key loaded! Fingerprint %s --- Is secret? %d\n", this->public_key_OMN_master->fpr, this->public_key_OMN_master->secret);



	//now let's load each known slave's personal key!
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
		fprintf(stdout, "Key loaded! Fingerprint %s --- Is secret? %d\n", tmp->fpr, tmp->secret);
		
	}
	
		
	//we got everything, let the crypto ops begin!

	
}

bool MasterCryptoCtx::import_new_slave_personal_key_public(char* gpg_import_filepath) {
	
	gpgme_data_t key_to_be_imported;
	
	bool done_correctly = false;

	if(gpgme_data_new_from_file(&key_to_be_imported, gpg_import_filepath, 1) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to open \"%s\".\n Maybe it doesn't exist or is already opened by some other program. Hence, we failed to create a gpgme data object\n", gpg_import_filepath);
		return false;
	}

	
	//let's import em!
	if(gpgme_op_import(this->gpgme_context, key_to_be_imported) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to import keys from file\n");
		return false;
	}
	
	//now we can print what we have imported!
	gpgme_import_result_t import_results = gpgme_op_import_result(this->gpgme_context);
	
	if(import_results != NULL) {
		fprintf(stdout, "Successfully imported %d keys (we considered %d)!\n", import_results->imported, import_results->considered);
	
		int temp_j = 0;
		
		gpgme_import_status_t temp_import = import_results->imports;

		std::list<std::string> list_of_imported_fingerprints;
		
		while(temp_import != NULL) {
			if(temp_import->result == GPG_ERR_NO_ERROR) {

				fprintf(stdout, "#%d imported ", temp_j);
				fprintf(stdout, "key: %s\n", temp_import->fpr);


				if(!(temp_import->status & GPGME_IMPORT_SECRET) && (temp_import->status & GPGME_IMPORT_NEW)) {
					list_of_imported_fingerprints.push_back(std::string(temp_import->fpr));
				} else {
					fprintf(stderr, "Ignoring imported secret key with fingerprint %s.\n", temp_import->fpr);
				}

			}

			temp_j++; 
			temp_import = temp_import->next;
		}


		for(std::string& tmp_fpr: list_of_imported_fingerprints) {
			//let's get the key...
			gpgme_key_t imported_key;

			if(gpgme_get_key(this->gpgme_context, tmp_fpr.c_str(), &imported_key, 0) != GPG_ERR_NO_ERROR) {
				fprintf(stderr, "Failed to retrieve imported key with fingerprint %s\n", tmp_fpr.c_str());
			} else {
				if(imported_key == NULL) {
					fprintf(stderr, "FAILED TO RETRIEVE IMPORTED KEY WITH FINGERPRINT %s\n", tmp_fpr.c_str());
				} else {
					bool keep_the_key = yes_or_no_choice("Do you want to keep and authorize the key?");

					if(!keep_the_key) {
						//we gotta remove the key... The user doesn't want it in its keyring.
						fprintf(stdout, "Deleting the key... ");
						if(gpgme_op_delete_ext(this->gpgme_context, imported_key, GPGME_DELETE_ALLOW_SECRET | GPGME_DELETE_FORCE) != GPG_ERR_NO_ERROR) {
							fprintf(stderr, "ERROR!!!!!\n Something went wrong while trying to delete the key with fingerprint %s!\n", tmp_fpr.c_str());
						} else {
							fprintf(stdout, "Key deleted!\n");
						}

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

							if(get_slaveId_gpgKey(NORM_id_of_slave_imported_key) == NULL) {


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
								this->m_slaveId_gpgKey[NORM_id_of_slave_imported_key] = imported_key;
								this->m_gpgKeyFingerprint_slaveNORMid[std::string(tmp_fpr.c_str())] = NORM_id_of_slave_imported_key;
								this->m_slaveNORMid_slaveLanName[NORM_id_of_slave_imported_key] = std::string(lan_name_of_slave_imported_key);

							} else {

								fprintf(stdout, "You already imported this key! Ignoring...\n");

							}
						} else {
							fprintf(stdout, "FAILED TO RECOGNIZE LAN NAME OF IMPORTED KEY'S SLAVE (fingerprint: %s)!\nCAN'T ADD IT TO THE CONFIG FILE!", tmp_fpr.c_str());
						}


					}
					
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


char* MasterCryptoCtx::export_all_slaves_personal_pubkeys(size_t* len) {
	
	//Export each pubkey
	gpgme_key_t v_exporting_pubkeys[this->m_slaveId_gpgKey.size() + 1] = {NULL}; //NULL terminated.
	int j = 0;
	for(pair<const NormNodeId, gpgme_key_t>& p_ID_pubkey: this->m_slaveId_gpgKey) {
		//1) add each key to the null-terminated vector.
		v_exporting_pubkeys[j] = p_ID_pubkey.second;
		j++;
	}
	//just to be sure...
	v_exporting_pubkeys[this->m_slaveId_gpgKey.size()] = NULL;

	//now export it
	
	gpgme_data_t keys_to_be_exported;
	
	if(gpgme_data_new(&keys_to_be_exported) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object in order to export all slave's personal public key!!\n");
		exit(-1);
	}


	//public key (only it!).
	if(gpgme_op_export_keys(this->gpgme_context, v_exporting_pubkeys, 0, keys_to_be_exported) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to export slave's pubkey\n");
		exit(-1);
	}
	
	char* data_tmp = gpgme_data_release_and_get_mem(keys_to_be_exported, len);	
		
	if(data_tmp == NULL) {
		fprintf(stderr, "Failed to release and get export memory\n");
	}

	//let's copy it "normally" freeable memory.
	
	char* data_tmp_2 = (char*) malloc(*len);
	
	if(data_tmp_2 == NULL) {
		fprintf(stderr, "Failed to allocate memory for exported keys\n");
	}
	memcpy(data_tmp_2, data_tmp, *len);

	//free the "gpgme" type memory.
	gpgme_free(data_tmp);

	return data_tmp_2;	


}




//we need to unreference the keys and destroy the context we created during the init function. 
//NOTE: A good remainder to programmers, that freeing other gpgme data (objects) with gpgme_free() and gpgme_data_release() is their responsibility!!!
void MasterCryptoCtx::destroy_crypto_context() {
	

	//let's unref even the searched key. The search returned a reference and we need to unref it!
	gpgme_key_unref(this->public_key_OMN_slaveGroup);
	gpgme_key_unref(this->secret_key_OMN_master);
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


int MasterCryptoCtx::get_number_of_known_slaves() {
	return this->m_slaveId_gpgKey.size();
}

gpgme_key_t MasterCryptoCtx::get_slaveId_gpgKey(NormNodeId slaveId) {

	auto search = this->m_slaveId_gpgKey.find(slaveId);

	if(search != this->m_slaveId_gpgKey.end()) {
		return this->m_slaveId_gpgKey[slaveId];
	} else {
		return NULL;
	}

}

//will check if the GPG fingerprint in input is one of the slave's personal keys
bool MasterCryptoCtx::is_fingerprint_known(std::string fpr) {
	
	auto search = this->m_gpgKeyFingerprint_slaveNORMid.find(fpr);

	if(search != this->m_gpgKeyFingerprint_slaveNORMid.end()) {
		return true;
	} else {
		return false;
	}


}

/*-------------------------------------------------------------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------DISCOVERY PHASE FUNCTIONS--------------------------------------------------------------*/
/*-------------------------------------------------------------------------------------------------------------------------------------------------------*/

void OMN_discovery(NormInstanceHandle instance, NormSessionHandle session, MasterCryptoCtx& master_crypto_ctx, std::vector<Data_slave>& nodesFound) {

    bool keepGoing = true;

    long number_of_slaves_already_authed = 0;

    //send first message of AUTH protocol (This way we can advertize ourselves as masters inside the session!).
    Auth1 auth1 = build_Auth1();
    NormObjectHandle h_NORMOBJECT_auth1 = send_Auth1(session, &auth1);
    bool last_TX_Auth1_purged = false;

    fprintf(stdout, "OMN: Starting discovery of nodes...\n process will last %d seconds...\n", DISCOVERY_TIME);
   
    struct timeval startingTime;
    struct timeval timeout;

    int retval;
    
    ProtoSystemTime(startingTime); //let's start counting time, the DISCOVERY phase will last DISCOVERY_TIME seconds!

    //let's get norm descriptor in order to not block when we call NormGetNextEvent()
    NormDescriptor fd_NORM = NormGetDescriptor(instance);

    //we will stay in this loop for DISCOVERY_TIME seconds!
    while (keepGoing)
    {

    	//we need to use select() to check asyncronously if the norm thread has any events for us!
    	//We do this by telling select we want him to check if the NORM file descriptor
    	//is ready for a read (by adding him to the set of file descriptor we want to check
    	//for a "read ready" state), with a waiting timeout of 3 second!
    	
	//let's initialize the timeout struct for the select().
	//wait up to SELECT_TIMEOUT seconds to "select()" timeout.
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
		fprintf(stdout, "DISCOVERY: select(): has returned an error\n"); //welp, can't do much!
	} else if(retval) { 
		//we need to read the NORM EVENT...

		fprintf(stdout, "DISCOVERY: select(): event is avaliable\n");


		NormEvent theEvent;
		if (!NormGetNextEvent(instance, &theEvent)) continue; //if NORM doesn't return an event, it's not an error...
								      //just continue!
		switch (theEvent.type){
			case NORM_RX_OBJECT_COMPLETED:	//we received a new NORM OBJECT: stream, file or data? We must check!
				{
					fprintf(stdout, "DISCOVERY: NORM_RX_OBJECT_COMPLETED event! A new OMN node? Let's check...\n");
					int received_challenge;
					char fingerprint_used_for_signature[FINGERPRINT_LENGTH] = {0};
					if(verify_Auth2(&theEvent, session, master_crypto_ctx, auth1, nodesFound, &received_challenge)) {
						//A slave just verified! Let's add it to the stack of found nodes!
						fprintf(stdout, "DISCOVERY: A slave just subscribed to the current OMN session, adding it to the list...\n");
						
						Data_slave tmp;
						if(nodesFound.size() < master_crypto_ctx.get_number_of_known_slaves()) { //add them only if they don't overcome the max stack dimension.
							tmp.his_NORMID = NormNodeGetId(NormObjectGetSender(theEvent.object));
							tmp.challengeReceivedFromHim = received_challenge;
							nodesFound.push_back(tmp);
						}
						
						number_of_slaves_already_authed++;
						
					} else {
						//it was another message... Ignore it!
						fprintf(stdout, "DISCOVERY: Someone sent a message via NORM, but it is not an OMN Auth2 response....\n");
					}
				}
				break;
			case NORM_REMOTE_SENDER_NEW:
				fprintf(stdout, "DISCOVERY: Late joiner! Re-sending Auth1... ");
				//reply message for new comers, those who already replied have
				//your ID stored (and be locked onto it!) and will not do it again!
				//Btw... We will do it only if the last Auth1 has been purged from transmission.
    				if(last_TX_Auth1_purged) {
					
					fprintf(stdout, "AS NEW\n");
					//if the last one has been purged, we must re-enqueue it!
					h_NORMOBJECT_auth1 = send_Auth1(session, &auth1);
					last_TX_Auth1_purged = false;
				} else {
					fprintf(stdout, "FROM CACHE\n");
					//if it wasn't purged, we can do a sort of "data carousel" by repeating the
					//trasmission of the cached Auth1 !!! NormDeveloperGuide pdf, page 6
					NormRequeueObject(session, h_NORMOBJECT_auth1);
				}
				break;
			case NORM_TX_OBJECT_PURGED:
				fprintf(stdout, "DISCOVERY: Auth1 NORM OBJECT Purged! ");
				//NORM just purged our Auth1 from sending queue!!!!
				last_TX_Auth1_purged = true;
				h_NORMOBJECT_auth1 = NORM_OBJECT_INVALID;
				break;
			default:
				TRACE("DISCOVERY: Got event type: %d\n", theEvent.type); 
		}  // end switch(theEvent.type)


	} else { //we enter there if retval == 0, which means select() has timed out while waiting for 
		 //NORM file descriptor to become read-ready!
		fprintf(stdout, "DISCOVERY: just a heads up, select() has timed out! Don't worry too much!\n");
	}

	//did we pass the DISCOVERY_TIME seconds??? Let's check the clock now and compute how much time has passed
	//since we started by sending the first Auth1 message!
	struct timeval currentTime;
	ProtoSystemTime(currentTime);
	//we check if we reached the number of all possible slaves too, to cut off some time...
   	if((currentTime.tv_sec - startingTime.tv_sec > DISCOVERY_TIME) || (number_of_slaves_already_authed >= master_crypto_ctx.m_gpgKeyFingerprint_slaveNORMid.size())) {
		keepGoing=false; //we will exit this while() cycle if we surpassed it!
	};

    }  // end while(keepGoing)

    //we can't receive any Auth2 anymore... Nor we can send copies of Auth1...
    //We can just forget about Auth1! We can wait for a NORM_TX_OBJECT_PURGED event
    //but it can take time... We can just Cancel the object transmission (if it has not been already purged!)
    if(!last_TX_Auth1_purged) NormObjectCancel(h_NORMOBJECT_auth1);
	
    fprintf(stdout, "DISCOVERY: Discovery phase ended.\n"); //JUST A HEADS UP, THE DISCOVERY PHASE CAN END WITHOUT FINDING ANY OMN SLAVES!
}


Auth1 build_Auth1(){ //no need for previous state information, no need for input! We just need to generate a random challenge!
	Auth1 tmp;

	tmp.rB = generate_random_number();
    	fprintf(stdout, "DISCOVERY: just generated random challenge %d\n", tmp.rB);

	return tmp;
}

//
/**   Auth protocol, 1: B -> A :	rB
 *    we need a pointer to msg because the data sent MUST be accessible till NORM_TX_OBJECT_PURGED event!
 */
NormObjectHandle send_Auth1(NormSessionHandle session, Auth1* msg) {
	
    	fprintf(stdout, "DISCOVERY: just sent Auth1 with random challenge %d\n", msg->rB);
	//Send Auth1 message "msg" via NORM, without signing and encrypting, without NORM_INFO.
	return NormDataEnqueue(session, (char*) msg, sizeof(Auth1), NULL, 0);

}


/**
 *	Function used to verify received data, in order to establish if it is a valid Auth2 message.
 *	IT DOES INDEED CHECK IF THE SENDER IS A VALID SLAVE (E.g. the signature contained in it is valid).
 *	Generally, if it returns true the commander will save the slave's NORM ID and its challenge, to later send them again via an Auth3 response!
 *
 *	\param event The NORM event, used to get the data and the NORM_ID of the (possible) slave.
 *	\param session The NORM session in which we received the data, used to get the localID for GPG verification purposes.
 *	\param auth1_sent The Auth1 message we originally sent, used for GPG verification purposes.
 *	\param received_challenge A valid pointer to a blank int meant to contain the challenge generated by the slave, filled out if the data passes the verification phase.
 *
 *	\return true if data in NORM event is a valid Auth2 message, false otherwise. 
 */
bool verify_Auth2(NormEvent* event, NormSessionHandle session, MasterCryptoCtx& master_crypto_ctx, Auth1 auth1_sent, std::vector<Data_slave>& nodes_already_authed, int* received_challenge) {

	/***************************************************************************************************************************/
	/*************************************************CHECKING GOOD FORMAT******************************************************/
	/***************************************************************************************************************************/

	NormObjectHandle obj = event->object;
	//1) object type MUST be NORM_OBJECT_DATA
	if(NormObjectGetType(obj) != NORM_OBJECT_DATA) {
		fprintf(stderr, "Message isn't an Auth2 slave response. NormObject was not NORM_OBJECT_DATA.\n");
		return false;
	}
	//2) NormSize MUST be shorter than sizeof(int) + 1024*1 (1 KB) bytes. Generally a detached ARMORED signature is shorter than 1KB.
	if(NormObjectGetSize(obj) >= (sizeof(int) + 1024)) {
		fprintf(stderr, "Message isn't an Auth2 slave response. NormObject was not shorter than 1028 bytes\n");
		return false;	
	}
	//3) NormSize MUST at least sizeof(int) + 566 bytes. Generally a detached UNARMORED signature is 566 bytes long. 
	//   OMN sends only ARMORED signatures, but we can use this information to create a lower boundary for the size of a valid Auth2 message.
	if(NormObjectGetSize(obj) < (sizeof(int) + 566)) {
		fprintf(stderr, "Message isn't an Auth2 slave response. NormObject was not longer than 570 bytes\n");
		return false;
	}

	fprintf(stdout, "Message contained a correcly formatted Auth2 message...\n");
	//Can't verify much more
	//Let's generate a valid Auth2 struct
	const char* data = NormDataAccessData(obj);
	

	//copy the random challenge from slave inside the Auth2 struct.
	memcpy((void *) received_challenge, (void *) data, sizeof(int));
	//copy the signature from slave inside the Auth2 struct...
	gpgme_data_t sig_for_auth2;

	//empty gpgme_data_t that will contain signature!
	if(gpgme_data_new(&sig_for_auth2) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain signature for Auth2 message!\n");
		exit(-1);
	}

	//let's fill it up with the real signature (the remaining part of the data: full data minus the first part, the random challenge, an int)!
	if(gpgme_data_write(sig_for_auth2,(void*) &(data[0 + sizeof(int)]), (NormObjectGetSize(obj) - sizeof(int)) ) == -1) {
		fprintf(stderr, "Failed to copy received Auth2 signature inside signature data object!\n");
		exit(-1);
	}

	fprintf(stdout, "Successfully wrote and prepared Auth2 data (received bytes: %ld), to be verified by OMN master...\nSignature is long %ld bytes...\n", NormObjectGetSize(obj), gpgme_data_seek(sig_for_auth2, 0, SEEK_CUR));

	//oook, let's reset the cursor to point at the start of sig_for_auth2, otherwise we are going to verify 0 bytes of data!
	//(it signs starting from current pointer position)
	gpgme_data_seek(sig_for_auth2, 0, SEEK_SET);

	/***************************************************************************************************************************/
	/***************************************************VERIFICATION PHASE******************************************************/
	/***************************************************************************************************************************/
	
	//Let's rebuild the original signed tuple: (Slave_Norm_id, challenge_sent_by_master_in_auth1, challenge_sent_by_slave_in_auth2)	
	//For OMN slaves, that would be "cleartext"
	

	gpgme_data_t cleartext;
	
	//create a new empty object for this purpose!
	if(gpgme_data_new(&cleartext) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain cleartext for Auth2 message!\n");
		exit(-1);
	}

	//Let's fill the cleartext as we said before...
	NormNodeId master_id = NormGetLocalNodeId(session);
	if(gpgme_data_write(cleartext, &master_id, sizeof(NormNodeId)) == -1) {	
		fprintf(stderr, "Failed to copy NormNodeId inside cleartext data object, for Auth2 message!\n");
		exit(-1);
	} else {	
		fprintf(stdout, "Successfully copied master's NORM id (%d)  inside cleartext data object, for Auth2 message!\n", master_id);
	}

	if(gpgme_data_write(cleartext, &(auth1_sent.rB), sizeof(int)) == -1) {
		fprintf(stderr, "Failed to copy random challenge sent by master inside cleartext data object, for Auth2 message!\n");
		exit(-1);
	} else {	
		fprintf(stdout, "Successfully copied random challenge (%d) sent by master inside cleartext data object, for Auth2 message!\n", auth1_sent.rB);
	}

	if(gpgme_data_write(cleartext, received_challenge, sizeof(int)) == -1) {
		fprintf(stderr, "Failed to copy random challenge generated by slave inside cleartext data object, for Auth2 message!\n");
		exit(-1);
	} else {	
		fprintf(stdout, "Successfully copied random challenge (%d) generated by slave inside cleartext data object, for Auth2 message!\n", *received_challenge);
	}

	
	//Ok, now that we filled the data, let's verify it...	
	fprintf(stdout, "Successfully wrote and prepared data (%ld bytes) to cleartext gpgme object!\n", gpgme_data_seek(cleartext, 0, SEEK_CUR));

	//always reset the cursor after the writes!
	gpgme_data_seek(cleartext, 0, SEEK_SET);
	
	//let the crypto ops begin!
	bool is_signaturevalid = false;
	//1. Let's verify the payload, so the master can check an authorized slave really sent it (authentication).
	//	
	//	we use detached signature, so we can send only it, as by protocol.
	

	if(gpgme_op_verify(master_crypto_ctx.gpgme_context, sig_for_auth2, cleartext, NULL) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to complete verification of the Auth2 signature!\n");
		
		gpgme_data_release(sig_for_auth2);
		gpgme_data_release(cleartext);
		
		return false;
	}


	gpgme_verify_result_t verification_results = gpgme_op_verify_result(master_crypto_ctx.gpgme_context);

	if(verification_results == NULL) {
		fprintf(stderr, "Failed to get verify results!\n");
		gpgme_data_release(sig_for_auth2);
		gpgme_data_release(cleartext);
		return false;
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

		if(!master_crypto_ctx.is_fingerprint_known(tmp_possible_signature_fpr)) {
		       	fprintf(stderr, "Signature was NOT made with one of the known slaves' personal key!\n");
			is_signaturevalid = false;	
		} else if(NormNodeGetId(NormObjectGetSender(event->object)) != master_crypto_ctx.m_gpgKeyFingerprint_slaveNORMid[tmp_possible_signature_fpr]) {
				//the sender's NORM id MUST BE the same as the one of the fingerprint (so the same as the one specified in the primary UID of the key with fingerprint "tmp_possible_signature_fpr")
				fprintf(stderr, "Signature was made with one of the known slaves' personal key, BUT THE SENDER NORMID IS NOT THE SAME AS THE ONE SPECIFIED IN THE SIGN KEY!!!! POSSIBLE REPLY ATTACK!!!\n");
				is_signaturevalid = false;
		} else {
			//it MUST NOT be one of the signature already seen. If we see again a fingerprint, then it is a replayed signature and someone is trying to auth his NORMID!!!
			for(Data_slave& d: nodes_already_authed) {
				if(std::string((master_crypto_ctx.get_slaveId_gpgKey(d.his_NORMID))->fpr)  == tmp_possible_signature_fpr) {
					fprintf(stderr, "Signature was made with one of the already-seen and known slaves' personal key! POSSIBLE REPLY ATTACK!!!\n");
					is_signaturevalid = false;
					break;
				}
			}
		}

		fprintf(stdout, "Signature was made with key with fingerprint %s\n", possible_signature->fpr);

		if(is_signaturevalid) {
			fprintf(stdout, "SIGNATURE IS VALID!!!\n");
       		}
	}

	//If is_signaturevalid is true, it means the slave responding is an authorized slave: we can say this because the signature
	//signs a string of bits that contains rB (the challenge we sent originally)! This challenge was generated randomly, so we can say
	//it is close to impossible that this is a replayed message!
	//The message is directed at us too! The signature was done on a message containing our master's ID too!
	/***************************************************************************************************************************/

	gpgme_data_release(sig_for_auth2);
	gpgme_data_release(cleartext);
	return is_signaturevalid;


}




/*-------------------------------------------------------------------------------------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------------------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------------------------------------------------------------------------------------*/



/*-------------------------------------------------------------------------------------------------------------------------------------------------------*/
/*-------------------------------------------------------------SEND COMMAND PHASE FUNCTIONS--------------------------------------------------------------*/
/*-------------------------------------------------------------------------------------------------------------------------------------------------------*/
NormObjectHandle OMN_sendCommand(NormInstanceHandle instance, NormSessionHandle session, MasterCryptoCtx& master_crypto_ctx, std::vector<Data_slave>& nodesFound,
			char** stringCommandToBeLaterFreed, Command command) {

	//we need to send back an Auth3 response.
	//Let's start by building one.
	
	Auth3 auth3 = build_Auth3(command, nodesFound, master_crypto_ctx);
	
	fprintf(stdout, "OMN SENDCOMMAND: sending command to all slaves!\n");
	//now we "stringify" auth3, by sending it!
	return send_Auth3(session, auth3, master_crypto_ctx, stringCommandToBeLaterFreed); //we need the ctx because we are going to encrypt some part of the auth3 message.


}

Auth3 build_Auth3(Command cmd, std::vector<Data_slave>& nodesFound, MasterCryptoCtx& master_crypto_ctx) {
	
	Auth3 tmp;
	
	/*
	fprintf(stdout, "-----------------------------\n");
	for(Data_slave d: nodesFound) fprintf(stdout, "node %d : challenge %d\n", d.his_NORMID, d.token_for_him);
	fprintf(stdout, "-----------------------------\n");
	*/
	for(long i=0; i < nodesFound.size(); i++) {
		nodesFound[i].token_for_him = generate_random_number();
	}
	/*
	fprintf(stdout, "-----------------------------\n");
	for(Data_slave d: nodesFound) fprintf(stdout, "node %d : challenge %d\n", d.his_NORMID, d.token_for_him);
	fprintf(stdout, "-----------------------------\n");
	*/
	//this one no. Don't encrypt them!
	//Let's create the signature.
	craft_Auth3_data(nodesFound, cmd, master_crypto_ctx, tmp.sigB__list_COMM, tmp.pKAgroup__list_COMM);
	return tmp;	
}

void craft_Auth3_data(std::vector<Data_slave>& nodesFound, Command cmd, MasterCryptoCtx& master_crypto_ctx, gpgme_data_t& sig_for_auth3, gpgme_data_t& encrypted_for_auth3) {

	gpgme_data_t cleartext;

	//empty cleartext that will contain all the three inputs of this functions, concatenated like this:
	// |stringified_list|stringified_command|	
	if(gpgme_data_new(&cleartext) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain cleartext for Auth3 message!\n");
		exit(-1);
	}

	//empty gpgme_data_t that will contain signature!
	if(gpgme_data_new(&sig_for_auth3) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain signature for Auth3 message!\n");
		exit(-1);
	}
	
	//empty gpgme_data_t that will contain the encrypted cleartext!
	if(gpgme_data_new(&encrypted_for_auth3) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain encrypted payload for Auth3 message!\n");
		exit(-1);
	}

	//Oook, we got the two empty data objects, let's fill 'em up!
	//First of all, let's fill the cleartext as we said before...
	size_t size_of_list_stringified;
	char* list_stringified = stringify_vector_of_Data_slave(nodesFound, size_of_list_stringified);
	if(gpgme_data_write(cleartext, list_stringified, size_of_list_stringified) == -1) {
		fprintf(stderr, "Failed to copy list of pairs (NormNodeId slave, challenge) inside cleartext data object, for Auth3 message!\n");
		exit(-1);
	} else {
		fprintf(stdout, "Successfully copied list of triplets (%ld bytes) inside cleartext data object, for Auth3 message!\n", size_of_list_stringified);
	}

	size_t size_of_command_stringified;
	char* command_stringified = stringify_command(cmd, size_of_command_stringified);
	if(gpgme_data_write(cleartext, command_stringified, size_of_command_stringified) == -1) {
		fprintf(stderr, "Failed to copy command inside cleartext data object, for Auth3 message!\n");
		exit(-1);
	} else {	
		fprintf(stdout, "Successfully copied command (%ld) inside cleartext data object, for Auth3 message!\n", size_of_command_stringified);
	}

	//just a check, better be a bit paranoid!
	size_t cleartext_should_be_this_bytes_long = size_of_list_stringified + size_of_command_stringified;
	size_t actual_size = gpgme_data_seek(cleartext, 0, SEEK_CUR);
	if(actual_size != cleartext_should_be_this_bytes_long) {
		fprintf(stderr, "Failed to write data to cleartext gpgme object correctly! Only wrote %ld bytes, should've wrote %ld!\n", actual_size, cleartext_should_be_this_bytes_long);
		exit(-1);
	}

	fprintf(stdout, "Successfully wrote and prepared data to cleartext gpgme object! Wrote %ld bytes!\n", actual_size);

	//oook, let's reset the cursor to point at the start of cleartext, otherwise we are going to sign 0 bytes of data!
	//(it signs starting from current pointer position)	
	gpgme_data_seek(cleartext, 0, SEEK_SET);

	//now we need to add the secret key of OMN master to the "signers" list.
	if(gpgme_signers_add(master_crypto_ctx.gpgme_context, master_crypto_ctx.secret_key_OMN_master) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to add master's secret key as a signer!\n");
		exit(-1);
	}
	
	fprintf(stdout, "Successfully added master's secret key as a signer\nNumber of keys used to sign: %d\n", 
			gpgme_signers_count(master_crypto_ctx.gpgme_context));

	//ok we're ready to sign! Detached signature since we are going to send ONLY the signature (without cleartext!)
	if(gpgme_op_sign(master_crypto_ctx.gpgme_context, cleartext, sig_for_auth3, GPGME_SIG_MODE_DETACH) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to sign Auth3 DATA!!!!\n");
		exit(-1);
	}

	//let's ripristinate (at the first byte) the pointer in the signature data_T object (right now is pointing at the last byte written!).
	gpgme_data_seek(sig_for_auth3, 0, SEEK_SET);


	gpgme_signers_clear(master_crypto_ctx.gpgme_context);

	fprintf(stdout, "Successfully signed cleartext gpgme object!\n");

	//now let's encrypt the data we just signed.
	//oook, let's reset the cursor to point at the start of cleartext, otherwise we are going to encrypt 0 bytes of data!
	gpgme_data_seek(cleartext, 0, SEEK_SET);
	
	gpgme_key_t recipients_keys[2] = {master_crypto_ctx.public_key_OMN_slaveGroup, NULL};
	
	if(gpgme_op_encrypt(master_crypto_ctx.gpgme_context, recipients_keys, 
				(gpgme_encrypt_flags_t) (GPGME_ENCRYPT_ALWAYS_TRUST, GPGME_ENCRYPT_NO_ENCRYPT_TO | GPGME_ENCRYPT_PREPARE),
				cleartext, encrypted_for_auth3) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to encrypt payload with slave's public key!\n");
		exit(-1);
	}
	
	fprintf(stdout, "Successfully encrypted cleartext gpgme object!\n");
	
	//let's reset the cursor to point at the start of the cyphertext.
	gpgme_data_seek(encrypted_for_auth3, 0, SEEK_SET);

	//we'll "free" in "gpgme terms" the gpgme_data_t sig_for_auth3 and encrypted_for_auth3 later... The user must use it before!
	//we still need to free the cleartext tho...
	gpgme_data_release(cleartext);

	//let's free the memory used for the "stringified" version of list and commands...
	free(list_stringified);
	free(command_stringified);

}


NormObjectHandle send_Auth3(NormSessionHandle session, Auth3& auth3, MasterCryptoCtx& master_crypto_ctx, char** msg) {
	//Ok! let's send the auth3 message. We will need to define a point of separation between the encrypted payload and the signed payload.
	//We'll do this just with a long at the start of the message, signifying the length of the encrypted payload.
	//The slave will need to sanitize it, since we'll send it in the clear.
	
	//1) Let's get the 2 gpgme_data_t object memory content.
	size_t length_of_cyphertext;
	char* cyphertext_to_be_sent = gpgme_data_release_and_get_mem(auth3.pKAgroup__list_COMM, &length_of_cyphertext);

	if(cyphertext_to_be_sent == NULL) {
		fprintf(stderr, "Failed to release auth3's gpgme data_t cyphertext object!\n");
		exit(-1);
	}

	size_t length_of_signature;
	char* signature_to_be_sent = gpgme_data_release_and_get_mem(auth3.sigB__list_COMM, &length_of_signature);

	if(signature_to_be_sent == NULL) {
		fprintf(stderr, "Failed to release auth3's gpgme data_t signature object!\n");
		exit(-1);
	}

	//2) now we add the two lengths, and check for overflow.
	size_t length_of_payload = 0;
	if(sizeof(size_t) == sizeof(unsigned long)) {
		size_t tmp = 0;
		if(__builtin_uaddl_overflow(length_of_signature, length_of_cyphertext, &tmp)) {
			fprintf(stderr, "Overflow occured when trying to create payload for auth3 message. Size of cyphertext: %ld. Size of signature: %ld.\n",
					length_of_cyphertext, length_of_signature);
			exit(-1);
		}
		
		if(__builtin_uaddl_overflow(tmp, sizeof(size_t), &length_of_payload)) {
			fprintf(stderr, "Overflow occured when trying to create payload for auth3 message. Size of cyphertext + signature: %ld. Size of size_t: %ld.\n",
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
	NormObjectHandle auth3_sent = NormDataEnqueue(session, *msg, length_of_payload, NULL, 0);

	fprintf(stdout, "Sent Auth3 message! Total bytes: %ld\n", length_of_payload);
	fprintf(stdout, "message:\n%s\n", *msg);


	gpgme_free(signature_to_be_sent);
	gpgme_free(cyphertext_to_be_sent);


	return auth3_sent;

}




/*-------------------------------------------------------------------------------------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------------------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------------------------------------------------------------------------------------*/



/**
 *	Function used to verify received data, in order to establish if it is a valid Auth4 message.
 *	IT DOES INDEED CHECK IF THE SENDER IS A VALID SLAVE (E.g. the signature contained in it is valid).
 *	Generally, if it returns true the master will proceed to process the results (save them to file, print them to screen, etc.)!
 *
 *	\param event The NORM event, used to get the data
 *	\param master_crypto_ctx parameter containing the gpgme context and gpgme key objects.
 *	\param generated_token_for_command The token we have (as masters) given to the slaves, for the current OMN session.
 *	\param response Will contain the received response, if the data in NORM event is a valid and authenticated Auth4 message.
 *
 *	\return true if data in NORM event is a valid Auth4 message, false otherwise.
 */
bool verify_Auth4(NormEvent* event, MasterCryptoCtx& master_crypto_ctx, int generated_token_for_command, Response& response, char** hash_of_encrypted_resp) {


	/***************************************************************************************************************************/
	/*************************************************CHECKING GOOD FORMAT******************************************************/
	/***************************************************************************************************************************/

	bool is_auth4_signature_valid = false; //this alone doesn't speak nothing about auth4 authenticity! The next however yes...
	bool is_auth4_currently_valid = false; //can only change to true if the sanitizing and correct token is present inside Auth4.

	NormObjectHandle obj = event->object;
	//1) object type MUST be NORM_OBJECT_DATA
	if(NormObjectGetType(obj) != NORM_OBJECT_DATA) {
		fprintf(stderr, "Message isn't an Auth4 master response. NormObject was not NORM_OBJECT_DATA.\n");
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
	//3) decrypt the payload, to get the response.
	
	//1)...
	gpgme_data_t cleartext_for_signature;
	
	//create a new empty object for this purpose!
	if(gpgme_data_new(&cleartext_for_signature) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to create new gpgme data object to contain cleartext (for signature) from Auth4 message!\n");
		exit(-1);
	}

	//first, fill it up with the token
	if(gpgme_data_write(cleartext_for_signature, &(generated_token_for_command), sizeof(int)) == -1) {	
		fprintf(stderr, "Failed to copy token inside cleartext (to be verified) data object, for Auth4 signature!\n");
		exit(-1);
	} else {	
		fprintf(stdout, "Successfully copied token (%d) inside cleartext data object, for Auth4 signature verification!\n", generated_token_for_command);
	
	}

	//then finish filling it up with the encrypted response (pKB_RESP)
	//to write pKB_RESP inside the cleartext_for_signature we first need to read the contents of the gpgme_data_t object that we crafted before.
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
	//we can now finish the filling of cleartext_for_signature
	if(gpgme_data_write(cleartext_for_signature, buf_pKB_RESP, length_of_cyphertext) == -1) {	
		fprintf(stderr, "Failed to copy encrypted response inside cleartext (to be verified) data object, for Auth4 signature!\n");
		exit(-1);
	} else {	
		fprintf(stdout, "Successfully copied encrypted response (%ld bytes) inside cleartext data object, in order to verify Auth4 signature!\n", length_of_cyphertext);
	}
	gpgme_data_seek(cleartext_for_signature, 0, SEEK_SET); //always ripristinate the cursor!


	bool is_signaturevalid = false;
	
	//2)Verify it!
	if(gpgme_op_verify(master_crypto_ctx.gpgme_context, received_auth4.sigA__tB_pKBRESP, cleartext_for_signature, NULL) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to complete verification of the Auth4 signature!\n");
		is_auth4_signature_valid = false;	
	}


	gpgme_verify_result_t verification_results = gpgme_op_verify_result(master_crypto_ctx.gpgme_context);

	if(verification_results == NULL) {
		fprintf(stderr, "Failed to get verify results!\n");
		is_auth4_signature_valid = false;
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

		if(!master_crypto_ctx.is_fingerprint_known(tmp_possible_signature_fpr)) {
		       	fprintf(stderr, "Signature was NOT made with one of the known slaves' personal key!\n");
			is_signaturevalid = false;	
		} else if(NormNodeGetId(NormObjectGetSender(event->object)) != master_crypto_ctx.m_gpgKeyFingerprint_slaveNORMid[tmp_possible_signature_fpr]) {
				//the sender's NORM id MUST BE the same as the one of the fingerprint (so the same as the one specified in the primary UID of the key with fingerprint "tmp_possible_signature_fpr")
				fprintf(stderr, "Signature was made with one of the known slaves' personal key, BUT THE SENDER NORMID IS NOT THE SAME AS THE ONE SPECIFIED IN THE SIGN KEY!!!! POSSIBLE REPLY ATTACK!!!\n");
				is_signaturevalid = false;
		} else {
			//"""it MUST NOT be one of the signature already seen. If we see again a fingerprint, then it is a replayed signature and someone is trying to auth his NORMID!!!"""
			/* No need for this check. The token is unique and can be used to auth only one valid response.
			 * After a response is authed, the token is automatically deleted. Thus, we can't use it to auth a replayed message, cause the token doesn't exist anymore!
			 * Even if an attacker were to try to use the signature of the replayed message, the attack would fail for 2 reasons:
			 * 	1) in "nodesFound" there is no more the association NodeID->token required to auth the replayed message.
			 * 	   this means "find_data_slave" fails.
			 * 	2) IF the attacker were to use its own NORM id, we got two cases:
			 * 		a) the NORM id is still contained in "nodesFound": the attack will fail because we expect a signature made from another key in respect to that of the replayed message (even if the tokens are the same, so we pass all the previous controls except the previous elseif!).
			 * 		b) the NORM id is not contained in "nodesFound": the attack will fail because there is no "nodeID->token" association (find_data_slave) fails. 
			 * 		   NOTE: This is the case for a replayed message coming from a "right" NORMid but whose token has been already consumed --> the NORM id is not (anymore) contained in "nodesFound"
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
	
	is_auth4_signature_valid = is_signaturevalid;
	
	gpgme_data_release(cleartext_for_signature);	
	free(buf_pKB_RESP);
	
	if(is_auth4_signature_valid) {
		//3)...
		gpgme_data_t cleartext;
		
		//create a new empty object for this purpose!
		if(gpgme_data_new(&cleartext) != GPG_ERR_NO_ERROR) {
			fprintf(stderr, "Failed to create new gpgme data object to contain response from Auth4 message!\n");
			exit(-1);
		}

		//fill it up with the decrypted cyphertext.
		if(gpgme_op_decrypt(master_crypto_ctx.gpgme_context, received_auth4.pKB_RESP, cleartext) != GPG_ERR_NO_ERROR) {
			fprintf(stderr, "Failed to decrypt message!\n");
			
		} else {
			bool is_ciphertextValid = true;
			gpgme_decrypt_result_t decryption_result = gpgme_op_decrypt_result(master_crypto_ctx.gpgme_context);
			//now we check that the recipient is one and one only: the public key of the master.
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

				//last check: The ciphertext must have been encrypted with the master's pubkey!
				//The results contain a keyid, not a fingerprint. We need to search for the fingerprint, and warn the user about possible duplicates!
				
				/* there MAY be a problem with this check (fingerprint(keyid) == fingerprint_of_masters_pubkey): It seems that gpg tries all secret keys inside the pc that it is running on:
				 * IF there are two keys in the same keyring with same keyid (lower 64 bits) there will be a collision! If one of the two keys has been compromised, an attacker
				 * could use this vulnerability to successfully encrypt and let the message pass as it was encrypted by the rightful key. We can only WARN the user about this!*/

				gpgme_key_t key_used_for_encryption;
				gpgme_error_t error_tmp = gpgme_get_key(master_crypto_ctx.gpgme_context, decryption_result->recipients->keyid, &key_used_for_encryption, 0); //get the public key used for encryption, OMN SLAVES AND MASTERS have both so, since decryption went ok, this control should return at this point.i
				
				if(error_tmp != GPG_ERR_NO_ERROR && gpgme_err_code(error_tmp) == GPG_ERR_AMBIGUOUS_NAME) {

					fprintf(stderr, "***WARNING***: YOU HAVE TWO OR MORE KEYS WITH SAME KEYID AS THE PUBKEY USED FOR OMN MASTERS! CONSIDER CHANGING THEM!\n");
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
					
					if(!(strcmp(key_used_for_encryption->fpr, master_crypto_ctx.public_key_OMN_master->fpr) == 0 )) {
						fprintf(stderr, "Ciphertext was NOT made with the master's public key!\nfingerprint of used key:%s\nfingerprint should be: %s\n", key_used_for_encryption->fpr, master_crypto_ctx.public_key_OMN_master->fpr);
						is_ciphertextValid = false;
					} else {
					
						fprintf(stderr, "OK! Ciphertext was made with the master's public key!\nfingerprint of used key:%s\nfingerprint should be: %s\n", key_used_for_encryption->fpr, master_crypto_ctx.public_key_OMN_master->fpr);
					
					}
						
					gpgme_key_unref(key_used_for_encryption);
				}


				if(is_ciphertextValid)	{	//if we here, then it's all ok: cyphertext has been encrypted with just 1 key,
								//and it's the master's pubkey!
					
					//2)...
					fprintf(stdout, "All ok! Encryption was made with key with fingerprint %s\n", decryption_result->recipients->keyid);
					fprintf(stdout, "Decryption successfull... proceeding to sanitize the response...!\n");

					//Ok, now that we filled the data, let's sanitize it...
					fprintf(stdout, "Successfully wrote and prepared data (%ld bytes) to cleartext gpgme object!\n", gpgme_data_seek(cleartext, 0, SEEK_CUR));

					//always reset the cursor after the writes!
					gpgme_data_seek(cleartext, 0, SEEK_SET);
					
					//let the sanitization ops begin!

					//let's get the cleartext data, in order to unstringify the response. 
					size_t cleartext_data_length = 0;
					char* cleartext_data = gpgme_data_release_and_get_mem(cleartext, &cleartext_data_length);	
					
					//first off, let's sanitize the data.
					if(sanitize_auth4_cleartext(cleartext_data, cleartext_data_length)) {
						fprintf(stderr, "Auth4 cleartext data successfully sanitized.\n");
						is_auth4_currently_valid = true;				

						if(is_auth4_currently_valid) {
							//ok last thing to do. If this is a valid auth4 message, without any problems, 
							//we can extrapolate the response...
							destringify_response(response, cleartext_data);
							//and save the hash (of the encrypted GPG message, not the decrypted RESPonse)
							char hash_of_current_result[gcry_md_get_algo_dlen(GCRY_MD_SHA256) + 1] = ""; //+1 for null terminator!!!
							gcry_md_hash_buffer(GCRY_MD_SHA256, hash_of_current_result, &(data[0 + sizeof(size_t)]), length_of_cyphertext);
							*hash_of_encrypted_resp = sha256_to_hexstring(hash_of_current_result);
						}
						//remember to release the memory of opt_data after processing the responses!


					}
				
					gpgme_free(cleartext_data);

				}
			}
		}
	}
	//If is_auth3_signature_valid is true, it means the cleartext contained a message signed by a valid master.
	//WE STILL DON'T KNOW IF IT IS OR NOT AN AUTH3 VALID MESSAGE BECAUSE SOMEONE COULD BE REPLYING AN OLD AUTH3 MESSAGE THAT DOESN'T CONTAIN THE
	//CURRECT LOCAL NORMID AND THE CHALLENGE WE SENT THIS TIME!

		
	
	
	/***************************************************************************************************************************/
	//we need to release all gpgme objects!
	gpgme_data_release(received_auth4.pKB_RESP);
	gpgme_data_release(received_auth4.sigA__tB_pKBRESP);

	return is_auth4_currently_valid;


}

bool sanitize_auth4_cleartext(char* cleartext, size_t length) {
	//1) let's get the response opt_data size. It is placed right after the response type.
		
	int opt_len_field = 0;
	size_t offset = 0 + sizeof(Response_type);

	//Now we check the possible "problem source", the opt_len field.

	memcpy(&opt_len_field, &(cleartext[offset]), sizeof(int));
	
	//it can be 0, but not negative!
	if(opt_len_field < 0) {	
		fprintf(stderr, "ERROR! Malformed auth4 cleartext: response's optional field length is negative!\n");
		return false;
	}
	//If it is valid, the optional field must be contained in the remaining part of the cleartext's memory buffer (the last part).
	size_t bytes_before_cmd_optional_field = sizeof(Response_type) + sizeof(int); //response type field length + opt_data length field sizes in bytes.
	
	size_t total_number_of_bytes_calculated = 0;
	if(__builtin_uaddl_overflow(bytes_before_cmd_optional_field, opt_len_field, &total_number_of_bytes_calculated )) {
		fprintf(stderr, "ERROR! Malformed auth4 cleartext: failed to get total bytes of cleartext according to the two variable fields' length; OVERFLOW IN ADDITION!\nBytes before response's optional field: %ld; Optional field length: %d", bytes_before_cmd_optional_field, opt_len_field);
		return false;
	}
	if(total_number_of_bytes_calculated != length) {
		fprintf(stderr, "ERROR! Malformed auth4 cleartext: calculated length via variable fields' lengths does not concide with length of cleartext data!\n");
		return false;
	}

	//if all the controls haven't failed, the data is safe.
	return true;
	

}






void OMN_receiveResults(NormInstanceHandle instance, NormSessionHandle session, MasterCryptoCtx& master_crypto_ctx, 
		std::vector<Data_slave>& nodesFound, std::vector<wrapper_response>& v_responses,
		NormObjectHandle& prev_auth3_normobject, char** stringCommandToBeLaterFreed,
		const char * directory, bool should_not_wait_for_deactivating_node){

	bool keepGoing = true;
	bool user_wants_to_exit = false;

	bool last_TX_Auth3_purged = false;

	int nodes_found_size_originally = nodesFound.size();

	fprintf(stdout, "OMN: Starting receive result phase...\n process will last till all results are received, press enter to quit!\n");

	struct timeval startingTime;
	struct timeval timeout;

	int retval;

	//ProtoSystemTime(startingTime); //WE DON'T COUNT TIME. RESULT PHASE LASTS INDIFINITELY, TILL ALL RESPONSES ARE RECEIVED.
					

	//let's get norm descriptor in order to not block when we call NormGetNextEvent()
	NormDescriptor fd_NORM = NormGetDescriptor(instance);

	//TODO: we'll use ncurses to exit this loop!
	while (keepGoing)
	{

	//we need to use select() to check asyncronously if the norm thread has any events for us!
	//We do this by telling select we want him to check if the NORM file descriptor
	//is ready for a read (by adding him to the set of file descriptor we want to check
	//for a "read ready" state), with a waiting timeout of 3 second!

	//let's initialize the timeout struct for the select().
	//wait up to SELECT_TIMEOUT seconds to "select()" timeout.
	timeout.tv_sec = SELECT_TIMEOUT;
	timeout.tv_usec = 0;

	//Now let's initialize the file descriptor read bucket!
	fd_set fdsetInput; 
	FD_ZERO(&fdsetInput); //we reset the bucket, everytime we want to check, cause the sets gets modified
	      //in place to indicate which file descriptors are currently ready (manpage)
	FD_SET(fd_NORM, &fdsetInput); //we add the NORM file descriptor to the set, cause we want to check him.
	FD_SET(0, &fdsetInput); //we add the stdin file descriptor to the set, cause we want to check him.

	//we don't want to check exceptional or write "ready" state for any fd, we leave those FD buckets as NULL.
	//we just want to check the input set!
	//the first one must be the highest file descriptor value in all buckets, plus 1...
	//ok... let's pass the timeout too and we ready to go! THIS CALL WILL NOT BLOCK!
	retval = select(fd_NORM+1, &fdsetInput, NULL, NULL, &timeout);


	//if retval is 1, that means fd_NORM has become ready for a read -> a NORM EVENT is waiting to be picked up!
	if(retval == -1) {
		fprintf(stdout, "RESULT: select(): has returned an error\n"); //welp, can't do much!
	} else if(retval) { 
		//we need to read the NORM EVENT...

		fprintf(stdout, "RESULT: select(): event is avaliable\n");

		if(FD_ISSET(0, &fdsetInput)) {
			//user pressed some button...
			user_wants_to_exit = true;
		} else {
			//else, it was the norm fd to be set
			NormEvent theEvent;
			if (!NormGetNextEvent(instance, &theEvent)) continue; //if NORM doesn't return an event, it's not an error...
								      //just continue!
			switch (theEvent.type){
			case NORM_RX_OBJECT_COMPLETED:	//we received a new NORM OBJECT: stream, file or data? We must check!
				{
					fprintf(stdout, "RESULT: NORM_RX_OBJECT_COMPLETED event! A new OMN result? Let's check...\n");
					wrapper_response tmp_wrp_rsp;
					long index_of_sender = 0;
					if(find_data_slave(nodesFound, NormNodeGetId(NormObjectGetSender(theEvent.object)), index_of_sender)) {
						
						char* rsp_encrypted_hash;
						if(verify_Auth4(&theEvent, master_crypto_ctx, nodesFound[index_of_sender].token_for_him, tmp_wrp_rsp.rsp, &rsp_encrypted_hash)) {
							//TODO: Add hash check to ignore duplicates!
							//A slave just sent a response! Let's add it to the stack of responses!
							fprintf(stdout, "RESULT: A slave just sent a result in the current OMN session, adding it to the list...\n");
						
							memcpy(tmp_wrp_rsp.hash_of_encrypted_version, rsp_encrypted_hash, SHA256_READABLE_LENGTH);	
							v_responses.push_back(tmp_wrp_rsp);	

							//gotta add the hash of the received encrypted cyphertext to the hidden mapfile, for backup/reconstruction of results.
							if(tmp_wrp_rsp.rsp.codename == NMAP_RESULT_FILE || tmp_wrp_rsp.rsp.codename == REQUESTED_FILE)
								add_to_hidden_mapfile(rsp_encrypted_hash, directory);
							
							free(rsp_encrypted_hash);

							//we consumed the token, can't use it anymore!
							nodesFound.erase(nodesFound.begin() + index_of_sender);

						} else {
							//it was another message... Ignore it!
							fprintf(stdout, "RESULT: Someone sent a message via NORM, but it is not an OMN Auth4 result message....\n");
						}
					} else {
						fprintf(stdout, "SEND RESULT: Received another message, but it was not from an authenticated norm ID! REJECTED!\n");
					}
				}
				break;
			case NORM_REMOTE_SENDER_NEW:
				fprintf(stderr, "RESULT: Late joiner! Can't do anything, command has already been sent!\n");
				break;
			case NORM_TX_OBJECT_PURGED:
				if(theEvent.object == prev_auth3_normobject) {
					fprintf(stdout, "RESULT: Auth3 NORM OBJECT Purged!\n");
					//NORM just purged our Auth3 we sent in the send command phase, from sending queue!!!!
					last_TX_Auth3_purged = true;
					prev_auth3_normobject = NORM_OBJECT_INVALID;
					//let's free the payload too!
					free(*stringCommandToBeLaterFreed);
				} else {
					fprintf(stderr, "RESULT: some NORM message has been purged...\n");
				}
				break;
			default:
				TRACE("RESULT: Got event type: %d\n", theEvent.type); 
			}  // end switch(theEvent.type)
		}

	} else { //we enter there if retval == 0, which means select() has timed out while waiting for 
	//NORM file descriptor to become read-ready!
		fprintf(stdout, "RESULT: just a heads up, select() has timed out! Don't worry too much!\n");
	}

	//did we receive all results? If yes, stop this iteration!
	if((nodes_found_size_originally - (should_not_wait_for_deactivating_node ? 1 : 0)) == v_responses.size() ) {
		keepGoing=false; //we will exit this while() cycle if we surpassed it!
	} else if(user_wants_to_exit) {
		keepGoing = false;	
	};

	}  // end while(keepGoing)



	//We can just forget about Auth3! We can wait for a NORM_TX_OBJECT_PURGED event
	//but it can take time... We can just Cancel the object transmission (if it has not been already purged!)
	if(!last_TX_Auth3_purged){
	       	NormObjectCancel(prev_auth3_normobject);	
		prev_auth3_normobject = NORM_OBJECT_INVALID;
		//let's free the payload too!
		free(*stringCommandToBeLaterFreed);
		last_TX_Auth3_purged = true;
	}
	
	fprintf(stdout, "RESULT: Receiving result phase ended. Got %ld/%d results.\n", v_responses.size(), nodes_found_size_originally); //JUST A HEADS UP, THE DISCOVERY PHASE CAN END WITHOUT FINDING ANY OMN SLAVES!


}



/*
NormNodeId auth_DISCOVERY_response(NormEvent event) {
	NormObjectHandle obj = event.object;
	//1) object type MUST be NORM_OBJECT_DATA
	if(NormObjectGetType(obj) != NORM_OBJECT_DATA) return INVALID_ID;
	//2) NormSize MUST be YYY bytes ONLY.
	if(NormObjectGetSize(obj) != ENCRYPTED_COMMAND_SIZE) return INVALID_ID;
	//3) authenticate data using slave public key
	//
	//4) decrypt data using master private key
	//
	//5) if command reads good, return NormNodeId
	return NormNodeGetId(event.sender);

}
*/








//null terminated directory!
void process_response(Response& r,const char* directory, bool should_save, OMN_db_status& master_db_stat) {
	static bool already_accessed_map_for_update = false; //if we get a RESULT_LIST response, the first one will overwrite the old
							     //mapping/distributed database status!

	switch(r.codename) {
		case NMAP_RESULT_FILE:
			fprintf(stdout, "Processing NMAP scan result to file...\n");
			//let's get the filename + content from the opt_data of the response...
			//those are just "fixed size" vectors, gotta sanitize them cause the content of opt_data isn't sanitized from receiver functions...
			//we only know that r.len indicated the true length of the memory allocated for r.opt_data!
			//gotta check we have space for at least the filename... the real filename will be LAN_NAME_LENGTH
			//but response.opt_data must contain in its first LAN_NAME_LENGTH bytes the LAN name from where the response originated!
			//We gotta see if we have at least LAN_NAME_LENGTH bytes in the opt_data... the rest will be the result file!
			if(r.len < LAN_NAME_LENGTH) {
				fprintf(stderr, "BADLY FORMATTED RESULT! DOES NOT CONTAIN THE LAN NAME! REJECTING!\n");
			} else {
				//in case it is == to LAN_NAME_LENGTH it does contain the lan name, but no result! impossible!
				char filename[LAN_NAME_LENGTH] = "";
				memcpy(filename, r.opt_data, LAN_NAME_LENGTH);
				filename[LAN_NAME_LENGTH - 1] = '\0';

				int remaining_bytes = r.len - LAN_NAME_LENGTH;
				if(remaining_bytes <= 0) {
					fprintf(stderr, "BADLY FORMATTED RESULT! DOES NOT CONTAIN THE RESULT! REJECTING!\n");
				} else {
					fprintf(stdout, "Correctly formatted result, saving it to file...\n");
					if(should_save)
						save_to_file(r.opt_data + LAN_NAME_LENGTH, remaining_bytes, filename, directory);
				}
			}
			break;
		case RESULT_LIST:
			{
				fprintf(stdout, "Processing NMAP result list...\n");
				//let's get the RESULT_NAME and the stringified map of results from the response.
				if(r.len < LAN_NAME_LENGTH) {
					fprintf(stderr, "BADLY FORMATTED RESULT! DOES NOT CONTAIN THE LAN NAME! REJECTING!\n");
				} else {
					char lan_of_result_list[LAN_NAME_LENGTH] = "";
					memcpy(lan_of_result_list, r.opt_data, LAN_NAME_LENGTH);
					
					OMN_slave_db_status db_status_of_this_slave;
					db_status_of_this_slave.owner = std::string(lan_of_result_list);

					//if we received a RESULT_LIST, there must be space for a stringified map!
					if(r.len == LAN_NAME_LENGTH) {
						fprintf(stderr, "BADLY FORMATTED RESULT! DOES NOT CONTAIN ANY RESULT LIST! REJECTING!\n");
					} else {
						//try to destringify the map...

						if(!(db_status_of_this_slave.destringify_slave_db_status(r.opt_data + LAN_NAME_LENGTH, master_db_stat.max_num_of_nodes, r.len - LAN_NAME_LENGTH))) {
							fprintf(stderr, "BADLY FORMATTED RESULT! DOES NOT CONTAIN A VALID RESULT LIST! REJECTING!\n");

						} else {
							//We got a valid map.
							
							//Let's check if we already overwrote the old db_status (during the current run of OMN).
							if(!already_accessed_map_for_update) {
								//if we didn't, then it means that we need to clear the previous DB status.
								master_db_stat.clear();
								already_accessed_map_for_update= true;
							}
						
							//we update the map first...
							master_db_stat.update_OMN_db_status_by_OMN_slave_db_status(db_status_of_this_slave);

							//then save it to file (again).
							master_db_stat.save_OMN_db_status();



							
						}

					}

				}

			}
			break;
		case REMOVE_SLAVE_RESULT:
			{
				if(r.len < (sizeof(int) + LAN_NAME_LENGTH)) {
					fprintf(stderr, "BADLY FORMATTED RESULT! DOES NOT CONTAIN THE NUMBER OF DELETED SLAVES AND LAN NAME OF SENDER! REJECTING!\n");
				} else {
					int deleted_slaves = 0;
					char lan_of_deleting_slave[LAN_NAME_LENGTH] = "";

					memcpy(&deleted_slaves, r.opt_data, sizeof(int));
					memcpy(lan_of_deleting_slave, r.opt_data + sizeof(int), LAN_NAME_LENGTH);

					fprintf(stdout, "The slave from lan %s has deleted %d keys.\n", lan_of_deleting_slave, deleted_slaves);
				}

			}
			break;
		case MY_LAN:
			{
				if(r.len < (LAN_NAME_LENGTH)) {
					fprintf(stderr, "BADLY FORMATTED RESULT! DOES NOT CONTAIN THE LAN NAME! REJECTING!\n");
				} else {
					char lan_slave[LAN_NAME_LENGTH] = "";

					memcpy(lan_slave, r.opt_data, LAN_NAME_LENGTH);

					fprintf(stdout, "Node replayed, lan \"%s\".\n", lan_slave);
				}

			}
			break;
		case FILE_NOT_FOUND:
			{
				if(r.len < (LAN_NAME_LENGTH)) {
					fprintf(stderr, "BADLY FORMATTED RESULT! DOES NOT CONTAIN THE LAN NAME! REJECTING!\n");
				} else {
					char lan_slave[LAN_NAME_LENGTH] = "";

					memcpy(lan_slave, r.opt_data, LAN_NAME_LENGTH);

					fprintf(stdout, "Requested file not found in the node, lan \"%s\".\n", lan_slave);
				}

			}
			break;
		case FILE_NOT_IN_THIS_NODE:
			{
				if(r.len < (LAN_NAME_LENGTH)) {
					fprintf(stderr, "BADLY FORMATTED RESULT! DOES NOT CONTAIN THE LAN NAME! REJECTING!\n");
				} else {
					char lan_slave[LAN_NAME_LENGTH] = "";

					memcpy(lan_slave, r.opt_data, LAN_NAME_LENGTH);

					fprintf(stdout, "Requested file was not in lan \"%s\", but its node still listened to get it.\n", lan_slave);
				}

			}
			break;
		case IMPORT_RESULT:
			{
				if(r.len < (sizeof(int) + LAN_NAME_LENGTH)) {
					fprintf(stderr, "BADLY FORMATTED RESULT! DOES NOT CONTAIN THE NUMBER OF IMPORTED KEYS AND LAN NAME OF SENDER! REJECTING!\n");
				} else {
					int imported_keys = 0;
					char lan_of_importing_slave[LAN_NAME_LENGTH] = "";

					memcpy(&imported_keys, r.opt_data, sizeof(int));
					memcpy(lan_of_importing_slave, r.opt_data + sizeof(int), LAN_NAME_LENGTH);

					fprintf(stdout, "The slave from lan %s has imported %d keys.\n", lan_of_importing_slave, imported_keys);
				}
			}
			break;
		default:
			//just print it to screen...
			fprintf(stdout, "Received response, but couldn't get codename...\n");
	}


}




/**
 *
 *	/param cmd Command, accessed only for its type. This function will free the memory associated with its opt_data!
 *	/param v_rsp Responses, accessed to manage all received responses.
 *	/param directory Null terminated string containing the name of the directory in which to save results. Can't be null if command is NMAP
 */
void process_results(std::vector<wrapper_response>& v_rsp, const char* directory, const char* accepting_hash, OMN_db_status& master_db_stat) {
	int i = 0;
	

	fprintf(stdout, "-------------\n");
	fprintf(stdout, "!!RESPONSES!!\n");
	fprintf(stdout, "-------------\n");
	for(wrapper_response& wrp_r : v_rsp) {
		//fprintf(stdout, "%d:%s\n",i++, r.opt_data);
		bool should_save = true;
		if(accepting_hash != NULL) {
			should_save = string(accepting_hash) == string(wrp_r.hash_of_encrypted_version);
			if(should_save)
				fprintf(stdout, "Hash %s is the same as requested, will save.\n", accepting_hash);
			else
				fprintf(stdout, "Hash is NOT the same as requested, will NOT save.\n");
		}

		process_response(wrp_r.rsp, directory, should_save, master_db_stat);

		if(wrp_r.rsp.len > 0) free(wrp_r.rsp.opt_data);
	}





}



void add_to_hidden_mapfile(char hash[SHA256_READABLE_LENGTH], const char* directory_of_results) {
	//We just append each hash of the encrypted RESPs we receive.
	//We will use this list for the backup/reconstruction command of OMN:
	//OMN will scan this list to see if there are any hashes we didn't catch 
	//during the OMN receive result phase of a particular scan!
	
	std::string filename_string = std::string(OMN_HIDDEN_MAPFILE_FILENAME);
	std::string directory_string = std::string(directory_of_results);

	std::string omn_filepath = std::string(getenv("HOME")) + "/" + std::string(OMN_DIRECTORY);
	std::string this_session_filepath = omn_filepath + "/" + directory_string;
	std::string hidden_mapfile_path = this_session_filepath + "/" + filename_string;

	//create folders if needed
	struct stat st = {0};
	if(stat(omn_filepath.c_str(), &st) == -1) {
		mkdir(omn_filepath.c_str(), 0775);
	}
	if(stat(this_session_filepath.c_str(), &st) == -1) {
		mkdir(this_session_filepath.c_str(), 0775);
	}

	FILE* fp = fopen(hidden_mapfile_path.c_str(), "ab");
	if(fp == NULL) fprintf(stderr, "Failed to open file %s\n", hidden_mapfile_path.c_str());
	else {

		fprintf(fp, "%s\n", hash); 
		fprintf(stdout, "Successfully printed hash %s inside file %s\n", hash, hidden_mapfile_path.c_str());
		fclose(fp);
	}
}

