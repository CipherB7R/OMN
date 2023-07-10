#include "OMN_common.h"
#include "stack.h"
#include "OMN_db.h"

#define INVALID_ID -2 //invalid discovery ID, for unauthorized clients.

//#define ENCRYPTED_COMMAND_SIZE 10 //bytes of cyphertext of a command, used in DISCOVERY response auth process.
#define GRACE_TIME 90  //grace time in seconds, granted to send result phase if the scan
		       //terminated but OMN couldn't send the results at least 1 time via NORM.
class SlaveCryptoCtx {
        public:
		NormNodeId local_NORMid;
                
		//context
                gpgme_ctx_t gpgme_context;

                //key management variables
                gpgme_key_t public_key_OMN_slaveGroup; 
                gpgme_key_t secret_key_OMN_slaveGroup; //USED TO DECRYPT (Auth3)
		gpgme_key_t public_key_OMN_slavePersonal;
                gpgme_key_t secret_key_OMN_slavePersonal; //USED TO SIGN (Auth4)
                gpgme_key_t public_key_OMN_master; //USED TO ENCRYPT (Auth4) AND VERIFY master's messages
		
		std::string my_lan_name; //used in pair with m_slave_gpgKey, 
					 //just to be sure that we don't import the current slave personal GPG key a second time.

                std::map<NormNodeId, gpgme_key_t> m_slaveId_gpgKey; //USED TO VERIFY (AUTH4)

                std::map<string, NormNodeId> m_gpgKeyFingerprint_slaveNORMid; //used in early stages of initialization and for reference after it!
		std::map<NormNodeId, string> m_slaveNORMid_slaveLanName;

                void init_crypto_context();
                void destroy_crypto_context();

                //will import into GPG the slave personal key inside the file with filepath.
		bool import_new_slave_personal_key_public(char* gpg_import_memory, size_t size_import, int& num_of_new_keys_imported);
		
		//if successfull, re-saves the entirety of the config file
        	bool remove_slave_pubkey(char* slave_pubkey_fpr, int& num_of_keys_deleted);
		bool is_fingerprint_known(std::string fpr); //will check if the GPG fingerprint in input is one of the slave's personal keys.
		int get_number_of_known_slaves(); //used to establish an upper limit on how many slaves we should wait.
                gpgme_key_t get_slaveId_gpgKey(NormNodeId slaveId);
	
	private:
		bool rebuild_config_file();
};



//the "crypto ops context" struct contains all variables a OMN slave needs when using GPG's crypto enviroment
//to sign and encrypt data he sends, and to verify and decrypt the one he receives!
/*
typedef struct {
	//key management variables
	gpgme_key_t public_key_OMN_slave; //Used to verify other OMN slave's messages.
	gpgme_key_t secret_key_OMN_slave; //USED TO SIGN
	gpgme_key_t public_key_OMN_master; //USED TO ENCRYPT (AND VERIFY MASTER'S MESSAGES)
	//gpgme context for the entire life of the application: used to communicate with GPG's engine, for encryption, decryption, signing and verification of messages!
	gpgme_ctx_t gpgme_slave_context;
} Crypto_ops_ctx; //when initialized, it will be valid through all application's lifetime!
*/



typedef struct {
	Command cmd;
	char * lan_name;
	bool response_avaliable;
	bool encryption_not_needed;
	SlaveCryptoCtx* slave_crypto_ctx;
	Response rsp;
} Execute_command_parms;

typedef struct {
	NormNodeId source;
	bool ptr_must_be_gpgme_freed;
	char* ptr;
	size_t size;
} EpkMaster_RESP;


//Functions for AUTH protocol, Master side only!
////DEPRECATED bool _verify_Auth1(NormSessionHandle session, Auth1 msg);
//NormObjectHandle send_Auth2(Auth2 msg); //Executed between pass 3 and 4 of AUTH algorythm.
//bool _verify_Auth3(NormSessionHandle session, Auth3 msg);
//NormObjectHandle send_Auth4(Auth4 msg); //Executed at the end of pass 4 of AUTH algorythm.


char * get_directory_where_to_save_results(Command cmd, int * len);
char * get_default_directory_name(Command cmd, int * len);


//returns a Data_lockedon_master struct with valid ID if theEvent contained an Auth1 message.
Data_lockedon_master wrapper_verify_Auth1(NormEvent* event);
//void wrapper_verify_Auth4(NormEvent* theEvent);

//--------------------------------AUTH2----------------------------------------------//
//we need the information received from the master, in order to create an Auth2 packet!
Auth2 build_Auth2(Data_lockedon_master* master, SlaveCryptoCtx& slave_crypto_ctx); 
NormObjectHandle send_Auth2(NormSessionHandle session, Auth2* msg, SlaveCryptoCtx& slave_crypto_ctx, char** payload);
//-----------------------------------------------------------------------------------//


//--------------------------------AUTH3----------------------------------------------//
bool verify_Auth3(NormEvent* event, NormSessionHandle session, SlaveCryptoCtx& slave_crypto_ctx, Data_lockedon_master* prev_authed_data, Command& command, std::vector<Data_slave>& otherSlaves);
bool sanitize_auth3_cleartext(char* cleartext, size_t length, size_t* command_offset);
//-----------------------------------------------------------------------------------//


//--------------------------------AUTH4----------------------------------------------//
Auth4 build_Auth4(Data_lockedon_master* master, Response rsp, SlaveCryptoCtx& slave_crypto_ctx);
NormObjectHandle send_Auth4(NormSessionHandle session, Auth4& auth4, SlaveCryptoCtx& slave_crypto_ctx, char** msg);
bool verify_Auth4(NormEvent* event, SlaveCryptoCtx& slave_crypto_ctx, int token_to_verify, char** response, size_t* length_of_response) ;
//-----------------------------------------------------------------------------------//

/**
 * Waits indefinitely for an Auth1 message, when he gets one, he sends Auth2 and locks onto it for 30 seconds.
 * He should receive a command after 15 seconds from when he sent Auth2.
 * The command is then returned as output.
 */
Command OMN_subscribe(NormInstanceHandle instance, NormSessionHandle session, SlaveCryptoCtx& slave_crypto_ctx, Data_lockedon_master* master, std::vector<Data_slave>& otherSlaves);

//crypto ops functions
SlaveCryptoCtx& init_crypto_context_slave(char lan_name[LAN_NAME_LENGTH]);
void destroy_crypto_context_slave(SlaveCryptoCtx& slave_crypto_context);


extern pthread_mutex_t gpgme_crypto_ctx_mutex;
extern pthread_mutex_t mutex_execute_command; //will be valid when execute_command gets called.
void* execute_command(void* params);

Response process_command(Command cmd, char* lan_name, SlaveCryptoCtx& slave_crypto_ctx, pthread_mutex_t* gpgme_crypto_ctx_mutex);

void process_RESPs(std::vector<EpkMaster_RESP> v_RESPs, Command cmd);

Command OMN_sendResult(NormInstanceHandle instance, NormSessionHandle session, SlaveCryptoCtx& slave_crypto_ctx, Data_lockedon_master* master, 
                Execute_command_parms* thread_exeCmd_params, pthread_t* thread_exeCmd_id, Command command, std::vector<Data_slave>& otherSlaves, 
                std::vector<EpkMaster_RESP>& v_RESPs);


std::string get_nmap_targets(bool only_ipv4);
std::string get_nmap_options();
std::string get_nmap_file_output_option();

//Command build_command(NormNodeId id_sender, Command_type type, char* opt_data, int len);

//NormObjectHandle send_command(Command cmd, NormSessionHandle session);
