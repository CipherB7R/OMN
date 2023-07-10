#include "OMN_common.h"
#include "stack.h"
#include "OMN_db.h"
#include <ncurses.h>

#define INVALID_ID -2 //invalid discovery ID, for unauthorized clients.

#define ENCRYPTED_COMMAND_SIZE 10 //bytes of cyphertext of a command, used in DISCOVERY response auth process.

typedef struct {
	NormNodeId client_who_sent_it;
	Response rsp;
} pair_response_normID;

typedef enum {INVALID_OPTION, SCAN, GET, DISTRIBUTE_SLAVE_PUBKEYS, IMPORT_A_SLAVE_PUBKEY, REMOVE_A_SLAVE, UPDATE, ACTIVE_SLAVES, KNOWN_SLAVES, PRINT_MASTER_INFO, HELP} longopts_OMN;



class MasterCryptoCtx {
	public:
		NormNodeId local_NORMid;
		string local_LAN_name;

		//context
		gpgme_ctx_t gpgme_context;

		//key management variables
		gpgme_key_t public_key_OMN_master;
		gpgme_key_t secret_key_OMN_master; //USED TO SIGN
		gpgme_key_t public_key_OMN_slaveGroup; //USED TO ENCRYPT (Auth3)
                
		std::map<NormNodeId, gpgme_key_t> m_slaveId_gpgKey; //USED TO VERIFY
		
                std::map<string, NormNodeId> m_gpgKeyFingerprint_slaveNORMid; //used in early stages of initialization and for reference after it!
		std::map<NormNodeId, string> m_slaveNORMid_slaveLanName;
	
		void init_crypto_context();
		void destroy_crypto_context();

		//will import into GPG the slave personal key inside the file with filepath.
		bool import_new_slave_personal_key_public(char* gpg_import_filepath);
		bool is_fingerprint_known(std::string fpr); //will check if the GPG fingerprint in input is one of the slave's personal keys.
		char* export_all_slaves_personal_pubkeys(size_t* len);
		void print_master_info();
		void print_slaves_info();

		int get_number_of_known_slaves(); //used to establish an upper limit on how many slaves we should wait.
		gpgme_key_t get_slaveId_gpgKey(NormNodeId slaveId);

        	bool remove_slave_pubkey(char* slave_pubkey_fpr, int& num_of_keys_deleted);
	
	private:
		bool rebuild_config_file();

};





string ncurses_selection_dialog(vector<string>& s);

longopts_OMN parse_argv(int argc, char** argv, char** option_argument);
void launch_OMN_command(Command cmd, OMN_db_status master_db_status, MasterCryptoCtx master_crypto_ops_ctx, const char result_name[RESULT_NAME_LENGTH], const char* accept_only_this_result_hash) ;


//crypto ops functions
//Functions for AUTH protocol, Master side only!
void OMN_discovery(NormInstanceHandle instance, NormSessionHandle session, MasterCryptoCtx& master_crypto_ctx, std::vector<Data_slave>& nodesFound);
Auth1 build_Auth1(); //no need for previous state information; We just need to generate a random challenge!
NormObjectHandle send_Auth1(NormSessionHandle session, Auth1* msg);


bool verify_Auth2(NormEvent* event, NormSessionHandle session, MasterCryptoCtx& master_crypto_ctx, Auth1 auth1_sent, std::vector<Data_slave>& nodes_already_authed, int* received_challenge);



NormObjectHandle OMN_sendCommand(NormInstanceHandle instance, NormSessionHandle session, MasterCryptoCtx& master_crypto_ctx, std::vector<Data_slave>& nodesFound,
			char** stringCommandToBeLaterFreed, Command command);

Auth3 build_Auth3(Command cmd, std::vector<Data_slave>& nodesFound, MasterCryptoCtx& master_crypto_ctx);
void craft_Auth3_data(std::vector<Data_slave>& nodesFound, Command cmd, MasterCryptoCtx& master_crypto_ctx, gpgme_data_t& sig_for_auth3, gpgme_data_t& encrypted_for_auth3);
NormObjectHandle send_Auth3(NormSessionHandle session, Auth3& auth3, MasterCryptoCtx& master_crypto_ctx, char** msg);


void OMN_receiveResults(NormInstanceHandle instance, NormSessionHandle session, MasterCryptoCtx& master_crypto_ctx, 
		std::vector<Data_slave>& nodesFound, std::vector<wrapper_response>& v_responses,
		NormObjectHandle& prev_auth3_normobject, char** stringCommandToBeLaterFreed,
		const char * directory, bool should_not_wait_for_deactivating_node);
bool verify_Auth4(NormEvent* event, MasterCryptoCtx& master_crypto_ctx, int generated_token_for_command, Response& response, char** hash_of_encrypted_resp);
bool sanitize_auth4_cleartext(char* cleartext, size_t length);
void process_response(Response& r, const char* directory, bool should_save, OMN_db_status& master_db_stat);
void process_results(std::vector<wrapper_response>& v_rsp, const char* directory, const char* accepting_hash, OMN_db_status& master_db_stat);
void add_to_hidden_mapfile(char hash[SHA256_READABLE_LENGTH], const char* directory_of_results);



