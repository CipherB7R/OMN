#ifndef OMN_COMMON_H

#define OMN_COMMON_H

#define __STDC_WANT_LIB_EXT1__ 1 //to use memcpy_s

#include "normApi.h"
#include "protoDefs.h"   // for ProtoSystemTime()
#include "protoDebug.h"  // for SetDebugLevel(), etc

#include <getopt.h>
#include <sys/random.h>  //for getrandom()
#include <sys/types.h>
#include <sys/stat.h>
#include <ifaddrs.h>	//to get interfaces addresses and construct nmap targets!
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wait.h>
#include <gcrypt.h>
#include <chrono>
#include <time.h>
#include <gpgme.h>	 // for GPG made easy, cryptography!
#include <stdio.h>       // for printf(), etc
#include <stdlib.h>      // for srand()
#include <string.h>      // for strrchr()
#include <unistd.h>	 // for sleep()
#include <locale.h>
#include <dirent.h>
#include <string.h> 	 // for memcpy_s()
#include <map>
#include <list>
#include <set>
#include <vector>
#include <string>
#include <iostream>

#define OMN_DIRECTORY "OMN"
#define DB_CURRENT_STATE_FILENAME ".client_results"
#define OMN_TMP_DIRECTORY "/tmp"
#define OMN_CFG_FILENAME "OMN.cfg"
#define OMN_HIDDEN_MAPFILE_FILENAME ".OMNreceived_hashes"
#define OMN_TMP_FILENAME_RESULT "temp_result.omn"
//#define MAX_CHAR_LAN_NAME 63 //max number of non null chars for the lan name


#define NMAP_RESULT_FILE_MAX_SIZE 10485760 //10MB --> max 200 (214 circa) full-size results can be contained in a single MULTIPLE_FILES Result (len field is only an int, 4 bytes).
					   //This is perfect, because we put a maximum of 200 OMN slaves per active session!
#define INVALID_ID -2


#define NEED_LIBGCRYPT_VERSION "1.8.0"


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//BE ADVISED: YOU'LL NEED TO WAIT AT LEAST DISCOVERY_SLAVE_TIMEMOUT seconds if you stop a master istance, cause you need to wait
//for SLAVES to "UNLOCK" from the old master instance you stopped!
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define DISCOVERY_TIME 15 //duration (in seconds) of MASTER's DISCOVERY phase, during which he searches for valid OMN slave nodes. 
			  //If OMN slaves receive Auth1 at mark DISCOVERY_TIME seconds and send their own Auth2,
			  //they will NOT get an AUTH3 Response (cause the master has already entered command send phase).

#define DISCOVERY_SLAVE_TIMEMOUT 30 //duration (in seconds) of SLAVE's timeout, after which all state pertaining to AUTH1
				    //will be dropped by the slave.
				    //SHOULD BE EQUAL TO DISCOVERY_TIME * 2, and at least (DISCOVERY_TIME + SELECT_TIMEOUT)+1 seconds.
				    //For the master this value means he has (DISCOVERY_SLAVE_TIMEMOUT - DISCOVERY_TIME) seconds after DISCOVERY PHASE to send the commands!

#define SELECT_TIMEOUT 3 //duration (in seconds) of select()'s timeout.


#define FINGERPRINT_LENGTH 41 //40 chars + null terminator.

//Scan results gets saved as "LANNAME_RESULTNAME"
#define LAN_NAME_LENGTH 128 //127 char + null terminator.
#define RESULT_NAME_LENGTH 128 //127 chars + null terminator. 

#define SENDRESULT_SLAVE_TIMEOUT 3600 //timeout for Send result phase, after which the slave will stop receiving results for the current OMN session.
				      //If the local scan hasn't come to an end, the send result phase timeout gets resetted 
				      //(giving it SENDRESULT_SLAVE_TIMEOUT seconds again).
				      //This is a default value. This value should be set by the Sysadmin
#define SHA256_READABLE_LENGTH 65 //64 + null terminator



extern const char* OMN_MULTICAST_IP;
extern const int  OMN_UDP_PORT; //Unused "Registered" port number.


//typedef enum {SCAN, GET_RESULTS} OMN_master_mode;
typedef enum {INVALID_COMMAND, NMAP, SEND_RESULT_LIST, SEND_FILE, SAY_LAN, IMPORT_SLAVE_PUBKEY, DELETE_SLAVE_PUBKEY} Command_type;
typedef enum {INVALID_RESPONSE, NMAP_RESULT_FILE, RESULT_LIST, REQUESTED_FILE, FILE_NOT_FOUND, FILE_NOT_IN_THIS_NODE, MY_LAN, IMPORT_RESULT, REMOVE_SLAVE_RESULT} Response_type; //Note: REQUESTED_FILE never gets sent. It is rather an indicator for OMN slaves function to send only the opt_data field, directly. 
														      			     //(It means response contains a previously received encrypted NMAP_RESULT_FILE response, so that response should be sent instead!)
																	     //Note2: FILE_NOT_IN_THIS_NODE never gets sent. It is rather an indicator for OMN slaves functions to wait for a response (from another slave)
																	     //that will contain it!

//Messages to be sent inside NORM_OBJECT_DATA (Response can be sent as NORM_INFO of NORM_OBJECT_FILE too!)
typedef struct { 
	Command_type codename;	
	char* opt_data; 
	int len; 	
} Command; //format of a master's command

typedef struct { 
	Response_type codename;	
	char* opt_data; //will contain the real result. I.e. a list of tuples (filename, hash)!
	int len;
} Response; //format of a slave's response (not a file result, those are stored by NORM directly in the file system!)


typedef struct { 
        char hash_of_encrypted_version[SHA256_READABLE_LENGTH]; 
        Response rsp; 
} wrapper_response;


typedef struct {
	char directory_where_to_save[RESULT_NAME_LENGTH];
} opt_data_NMAP;

typedef struct {
	char lan_name_of_executor[LAN_NAME_LENGTH];
	char directory[RESULT_NAME_LENGTH];
	char hash_filename[SHA256_READABLE_LENGTH];
} opt_data_SEND_FILE;

//no opt data for SEND_RESULT
typedef struct{
	char result_directory[RESULT_NAME_LENGTH];
	int num_files_in_this_directory; //max DIM_STACK
	char * file_list; //points to many num_files_in_this_directory hashes, whose length is SHA256_READABLE_LENGTH.
} opt_data_RESULT_LIST_element;

typedef struct {
	char lan_name_of_executor[LAN_NAME_LENGTH];
	char *stringified_opt_data_RESULT_LIST_elements;
} opt_data_RESULT_LIST;


typedef struct {

    NormNodeId his_NORMID;
    int challengeSentToHim;
    int challengeReceivedFromHim;
    Response responseReceivedFromHim;
    int his_token;
    long num_of_active_slaves; //including local node!!!!!

    bool authed; //true if node is authed, false otherwise. 
} Data_lockedon_master; //meant principally for slaves, to keep state about which master sent the Auth1 protocol message.





/**
 * The next 4 structures represent the 4 possible NORM_OBJECT_DATA payloads.
 * They are not exacly sent and received like this (apart Auth1) because they are sent as a
 * string of concatenated bits (like rA | signature).
 * They are meant for local marshalling between functions:
 * 	Normally we receive a string of concatenated bits, inside a NormEvent variable;
 *
 * 	We pass this NormEvent to a "verify()" function, this wrapper converts the string into
 * 		the following 4 structs;
 *
 * 	the "verify()" function accepts on of these 4 struct as input, and verifies them;
 *
 * 	The result is a boolean of verification results, which the wrapper function will use accordingly.
 *
 *
 * The 4 structures below are the four messages sent by the auth algorythm.
 * 
 * NOTATION USED:
 * B is the master (B is master's NORM ID), A is a slave (A is slave's NORM ID).
 *
 * sigX(...)	Signs with X private key the payload ...
 *
 * rX 	 is the random challenge proposed by X
 * tX 	 is the token generated by X to be signed by the receiver R to auth anything R will send afterwards.
 * COMM  is the command (only masters can send them)
 * list  is a list of normIDs of slaves, tokens for them and random challenges sent by them
 * pkBRESP is the result of the execution of COMM, encrypted with B's publick key, 
 * 	   which can be a short message (Response struct) or a file, but always a string of bits of variable length.
 *
 * 1: B -> A 	: 	rB
 * 2: A -> B	:	rA, sigA(B, rB, rA) 
 * 3: B -> A	:	tB, COMM, sigB(list, COMM)
 * 4: A -> B	:	fB, sigA(tB, fB)
 */
typedef struct {
	int rB; //random challenge from master (rMaster)
} Auth1; //Message 1 from AUTH algorythm. To be sent by master.

typedef struct {
	int rA; //random challenge from slave
	gpgme_data_t sigA__B_rB_rA; //sigSLAVE(MASTER_ID, rMaster, rSlave), only signature (no data)
} Auth2; //Message 2 from AUTH algorythm. To be sent by slave.

typedef struct { 
	gpgme_data_t pKAgroup__list_COMM;
	gpgme_data_t sigB__list_COMM;
} Auth3; //Message 3 from AUTH algorythm, command! To be sent by master.

typedef struct { 
	gpgme_data_t sigA__tB_pKBRESP; //sigSLAVE(token, pKB_RESP)
	gpgme_data_t pKB_RESP;
} Auth4; //Message 4 from AUTH algorythm, results! To be sent by slave.




//wrapper for NormCreateSession.
NormSessionHandle OMNCreateSession(NormInstanceHandle h_instance, NormNodeId local_NORM_ID);


//remember to free the returned pointer
char* stringify_command(Command& cmd, size_t& string_length);
void destringify_command(Command& destination, char* sv);
//remember to free the returned pointer
char* stringify_response(Response& rsp, size_t& string_length);
void destringify_response(Response& destination, char* sv);


//OMN saves the results he receives inside a OMN folder, under a directory with a chosen name/default date name, as its hashes (slaves) or real filename (only masters, who can decrypt the files!)
bool yes_or_no_choice(const char* question);
bool check_if_file_exists(const char* filepath);
bool check_if_result_exists(const char* filename, const char* directory);
bool delete_file(const char* filename, const char* directory);
void save_to_file(char* data, size_t len, const char* filename, const char* directory);
char* read_file(size_t* len, const char* filename, const char* directory);
char* sha256_to_hexstring(char* digest) ;
void init_gcrypt(void);
void init_gpgme (void);
int generate_random_number();
NormNodeId generate_local_id();
NormSessionId generate_session_id();

void opt_data_SEND_FILE_get(Command cmd, opt_data_SEND_FILE& dst);


void print_result_to_screen(gpgme_data_t out);
gpgme_error_t trust_interaction_func_automatic(void* handle, const char* status, const char* args, int fd);
gpgme_error_t trust_interaction_func_interactive(void* handle, const char* status, const char* args, int fd);
#endif
