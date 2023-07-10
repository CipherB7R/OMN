/* 
 g++ -o normFileSend normFileSend.cpp -D_FILE_OFFSET_BITS=64 -I../common/ \
     -I../protolib/include ../lib/libnorm.a ../protolib/lib/libProtokit.a \
     -lpthread
     
     (for MacOS/BSD, add "-lresolv")
     (for Solaris, add "-lnsl -lsocket -lresolv")

******************************************************************************/            


#include "OMN_masters.h"  // for Common OMN definitions


#ifdef WIN32
const char DIR_DELIMITER = '\\';
#else
const char DIR_DELIMITER = '/';
#endif // if/else WIN32/UNIX



int main(int argc, char* argv[])
{


	//0) Initialize the GPGME engine.
	init_gcrypt(); 
	init_gpgme();
	MasterCryptoCtx master_crypto_ops_ctx;

	master_crypto_ops_ctx.init_crypto_context();

	OMN_db_status master_db_status = OMN_db_status(master_crypto_ops_ctx.get_number_of_known_slaves());
	bool we_got_db_status = master_db_status.get_OMN_db_status();

	//1) Parse the input...
	char* option_argument = NULL;
	longopts_OMN longopt_of_user = parse_argv(argc, argv, &option_argument);

	switch(longopt_of_user) {
		case SCAN:
			{
				if(strlen(option_argument) >= RESULT_NAME_LENGTH) {
					fprintf(stderr, "Result name must not be longer than %d chars.\n", RESULT_NAME_LENGTH - 1);
				} else {
					char result_name[RESULT_NAME_LENGTH] = "";
					memcpy(result_name, option_argument, strlen(option_argument));
					

					Command OMNcommand = {NMAP, NULL, RESULT_NAME_LENGTH};
					OMNcommand.opt_data = (char*) calloc(1, RESULT_NAME_LENGTH);
					if(OMNcommand.opt_data == NULL) {
						fprintf(stdout, "Failed to allocate memory for optional data.\n");
						exit(-1);
					}
					memcpy(OMNcommand.opt_data, result_name, RESULT_NAME_LENGTH);

					launch_OMN_command(OMNcommand, master_db_status, master_crypto_ops_ctx, result_name, NULL);

				}
			}
			fprintf(stdout, "SCAN: RESULT WILL BE PLACED INSIDE OMN FILEPATH %s!\n", option_argument);
			break;
		case GET:
			{
				//TODO: ncurses to select which database to reconstruct
				//1) print info about last update
				if(we_got_db_status) {
					
					fprintf(stdout, "Last update of DB status: %s\n", master_db_status.last_modify.c_str());
					fprintf(stdout, "Press enter to acknowledge and continue...\n");
					getchar();
					//2) ncurses to select which result to "reconstruct"
					vector<string> all_avaliable_results;

					for(auto& p: master_db_status) {
						all_avaliable_results.push_back(p.first); //insert all results names.
					}
					string result_name_to_be_reconstructed = ncurses_selection_dialog(all_avaliable_results);

					//3) check if the hidden file exist	
					std::string filename_string = std::string(OMN_HIDDEN_MAPFILE_FILENAME);
					std::string omn_filepath = std::string(getenv("HOME")) + "/" + std::string(OMN_DIRECTORY);
					std::string this_session_filepath = omn_filepath + "/" + result_name_to_be_reconstructed;
					std::string hidden_mapfile_path = this_session_filepath + "/" + filename_string;

					bool hidden_file_name_exists = check_if_file_exists(hidden_mapfile_path.c_str());
					//4) build a list of hashes to download based on information gathered at (3)

					set<string> hashes_to_download;
					//I) fill up the set
					for(auto& p2: master_db_status[result_name_to_be_reconstructed])
						hashes_to_download.insert(p2.first);
					
					if(hidden_file_name_exists) {
						//don't download the hashes we already have!
						//II) erase the elements present in the hidden file name
						FILE* fp = fopen(hidden_mapfile_path.c_str(), "r");

						if(fp == NULL) fprintf(stderr, "Failed to open file %s\n", hidden_mapfile_path.c_str());
						else {

							char hash[SHA256_READABLE_LENGTH] = "";

							while(fscanf(fp, "%64s\n", hash) == 1) {
								fprintf(stdout, "You already have file with hash %s\n", hash);
								
								hashes_to_download.erase(string(hash));
							}
							fclose(fp);
						}

					}

					//5) reconstruct missing files
					for(const string& h: hashes_to_download) {
						//I) pick a random LAN and tell him to give you that file.
						fprintf(stdout, "Rebuilding hash %s\n", h.c_str());	
						auto tmp_set_iterator = next((master_db_status[result_name_to_be_reconstructed])[h].begin(), generate_random_number()  % (master_db_status[result_name_to_be_reconstructed])[h].size());


						string LAN_to_command = *tmp_set_iterator;

						Command OMNcommand = {SEND_FILE, NULL, sizeof(opt_data_SEND_FILE)};
						OMNcommand.opt_data = (char*) calloc(1, sizeof(opt_data_SEND_FILE));
						if(OMNcommand.opt_data == NULL) {
							fprintf(stdout, "Failed to allocate memory for optional data.\n");
							exit(-1);
						}
						opt_data_SEND_FILE tmp_opt = {"","",""};

						memcpy(&(tmp_opt.lan_name_of_executor), LAN_to_command.c_str(), LAN_to_command.length() >= LAN_NAME_LENGTH ? LAN_NAME_LENGTH - 1 : LAN_to_command.length());
						memcpy(&(tmp_opt.directory), result_name_to_be_reconstructed.c_str(), result_name_to_be_reconstructed.length() >= RESULT_NAME_LENGTH ? RESULT_NAME_LENGTH - 1 : result_name_to_be_reconstructed.length());
						memcpy(&(tmp_opt.hash_filename), h.c_str(), h.length() >= SHA256_READABLE_LENGTH ? SHA256_READABLE_LENGTH - 1 : h.length());


						memcpy(OMNcommand.opt_data, &tmp_opt, sizeof(opt_data_SEND_FILE));
						
						launch_OMN_command(OMNcommand, master_db_status, master_crypto_ops_ctx, result_name_to_be_reconstructed.c_str(), h.c_str());


					}

				} else {
					fprintf(stderr, "Can not GET results. OMN DB status is invalid.\n");
				}

			}
			break;
		case IMPORT_A_SLAVE_PUBKEY:
			{
				master_crypto_ops_ctx.import_new_slave_personal_key_public(option_argument);
			}
			break;
		case UPDATE:
			{
	    			Command OMNcommand = {SEND_RESULT_LIST, NULL, 0};
				launch_OMN_command(OMNcommand, master_db_status, master_crypto_ops_ctx, NULL, NULL);
			}
			break;
		case REMOVE_A_SLAVE: 
			{
				fprintf(stdout, "REMOVING A SLAVE...\n");
				//1) choose the slave to remove
				vector<string> all_avaliable_slaves;
				map<string, NormNodeId> reversed_lookup_map;

				for(auto& p: master_crypto_ops_ctx.m_slaveNORMid_slaveLanName) {
					all_avaliable_slaves.push_back(p.second); //insert all slaves lan names.
					reversed_lookup_map[p.second] = p.first;
				}

				string result_name_to_be_reconstructed = ncurses_selection_dialog(all_avaliable_slaves);
				
				//2) remove it from the network.	
				char deleting_slave_fingerprint[FINGERPRINT_LENGTH] = "";
				memcpy(deleting_slave_fingerprint, master_crypto_ops_ctx.m_slaveId_gpgKey[reversed_lookup_map[result_name_to_be_reconstructed]]->fpr, FINGERPRINT_LENGTH);

				Command OMNcommand = {DELETE_SLAVE_PUBKEY, NULL, FINGERPRINT_LENGTH};
				OMNcommand.opt_data = (char*) calloc(1, FINGERPRINT_LENGTH);
				if(OMNcommand.opt_data == NULL) {
					fprintf(stdout, "Failed to allocate memory for optional data.\n");
					exit(-1);
				}
				memcpy(OMNcommand.opt_data, deleting_slave_fingerprint, FINGERPRINT_LENGTH);

				launch_OMN_command(OMNcommand, master_db_status, master_crypto_ops_ctx, NULL, NULL);
				
				//3) remove it from the local crypto context
				int num_of_deleted_slaves = 0;
				master_crypto_ops_ctx.remove_slave_pubkey(master_crypto_ops_ctx.m_slaveId_gpgKey[reversed_lookup_map[result_name_to_be_reconstructed]]->fpr, num_of_deleted_slaves);
				fprintf(stdout, "Successfully deleted %d slaves\n", num_of_deleted_slaves);
				

			}
			break;	    
		case DISTRIBUTE_SLAVE_PUBKEYS:
			fprintf(stdout, "DISTRIBUTING OMN SLAVES'S PUBKEYS AMONG ALL SLAVES!\n");	
			{
				Command OMNcommand = {IMPORT_SLAVE_PUBKEY, NULL, 0};
				size_t export_size = 0;
	    			//let's just export each slave public key.
				OMNcommand.opt_data = master_crypto_ops_ctx.export_all_slaves_personal_pubkeys(&export_size);
				
				if(export_size >= INT_MAX) {
					fprintf(stderr, "Can't send opt_data bigger than %d in multicast. Exiting OMN.\n", INT_MAX);
				} else {	
					
					OMNcommand.len = export_size;
					if(export_size > 0) {
						launch_OMN_command(OMNcommand, master_db_status, master_crypto_ops_ctx, NULL, NULL);
					} else {
						fprintf(stderr, "No keys to be exported...\n");
					}
				}

			}
			break;
		case ACTIVE_SLAVES:
			fprintf(stdout, "PRINTING ACTIVE SLAVES IN LAN!\n");		
			{
	    			Command OMNcommand = {SAY_LAN, NULL, 0};
				launch_OMN_command(OMNcommand, master_db_status, master_crypto_ops_ctx, NULL, NULL);
			}
			break;
		case KNOWN_SLAVES:
			fprintf(stdout, "PRINTING KNOWN SLAVES!\n");		
			{
				//Just print all info in the master_crypto_ops_ctx
				master_crypto_ops_ctx.print_slaves_info();
				
			}
		case PRINT_MASTER_INFO:
			fprintf(stdout, "PRINTING MASTER INFORMATION!\n");		
			{
				master_crypto_ops_ctx.print_master_info();	
			}
			break;
		case HELP:
			fprintf(stdout, "Usage: %s [COMMAND]\n\n", argv[0]);
			fprintf(stdout, "Possible commands:\n");
			fprintf(stdout, "\t-s [RESULT NAME], --scan [RESULT NAME] :\n"
					"\t\tStarts NMAP scan on all active OMN slaves' LAN and puts the results under \"RESULT NAME\" subfolder of OMN.\n");
			fprintf(stdout, "\t-g,  --get:\n"
					"\t\tTries to reconstruct/fix missing files of some past scan, with active OMN slaves' distributed database.\n"
				        "\t\tThe user has to choose which scan to reconstruct through a ncurses choosing dialog.\n");
			fprintf(stdout, "\t-i [GPG EXPORTED PUBKEY FILE], --import-slave-pubkey [GPG EXPORTED PUBKEY FILE] :\n"
					"\t\tImports a slave's pubkey contained inside \"GPG EXPORTED PUBKEY FILE\" filepath\n");
			fprintf(stdout, "\t-u, --update :\n"
					"\t\tUpdates OMN distributed database status (available files, slaves etc.)\n");
			fprintf(stdout, "\t-d, --distribute-slave-pubkeys :\n"
					"\t\tDistributes all known slaves pubkeys to other slaves. Generally, it's used after you installed OMN on all slaves and imported\n"
				        "\t\tall their pubkeys in the master's keyring, or after importing a new slave key.\n");
			fprintf(stdout, "\t-r, --remove-slave:\n"
					"\t\tRemoves a slave choosen by the sysadmin from the OMN framework. It will remove the slaves pubkeys from the local GPG's keyring\n"
				        "\t\tand from all active slaves in the network.\n");
			fprintf(stdout, "\t-a, --active-slaves :\n"
					"\t\tDoes a quick check over OMN infrastructure, printing all active slaves' information.\n");
			fprintf(stdout, "\t-k, --known-slaves :\n"
					"\t\tPrints all locally known slaves' information (LAN names, NORM IDs, GPG pubkey's fingerprints). DOES NOT SEND ANY OMN COMMAND.\n");
			break;
		default:
			//unrecognized
			fprintf(stderr, "Unrecognized long option!\n");
	}


	master_crypto_ops_ctx.destroy_crypto_context();

	return 0;
}  // end main()
