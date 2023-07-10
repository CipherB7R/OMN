#include "OMN_common.h"


//ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);


const char* OMN_MULTICAST_IP = "239.192.0.66";
const int  OMN_UDP_PORT = 8970; //Unused "Registered" port number.


bool yes_or_no_choice(const char* question) {

	bool reask = true;

	while(true) {
		int c = 0;		
		
		fprintf(stdout, "%s Yes[1]/No[0] ", question);
		scanf("%d", &c);

		switch(c) {
			case 1:
				return true;
			case 0:
				return false;
			default:
				fprintf(stdout, "\nAnswer not recognized, retry.\n");
		}
	}


}


/** generates a random number using getrandom() and /dev/urandom source.
 *  According to getrandom manpage:
 *  these bytes can be used to seed user-space random number generators or for cryptographic purposes.
 *
 *  OMN uses this function to generate result tokens and challenges.
 */
int generate_random_number() {
	int generated;
	
	if(getrandom(&generated, sizeof(int), 0) == -1) exit(-1);

	return generated;
}

/** generates a random NORM local_id for the node
 */
NormNodeId generate_local_id(){

	NormNodeId nodeId = (NormNodeId)generate_random_number();
	return nodeId;
}

/** generates a random NORM session_id for the node
 */
NormSessionId generate_session_id() {
	NormSessionId sessionId = (NormSessionId)generate_random_number();
	return sessionId;
}

//digest contains a 32 byte digest. Output will contain 64 chars.
char* sha256_to_hexstring(char* digest) {
	//for each byte, we get 2 chars (2 hex values)
	char * string = (char*) malloc(SHA256_READABLE_LENGTH);
	
	if(string == NULL) {
		fprintf(stderr, "Failed to allocate space for converting digest in hex string.\n");
		exit(-1);
	}

	string[SHA256_READABLE_LENGTH - 1] = '\0';

	char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	
	for(int i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_SHA256) ; i++) {
		//pick a byte.
		char current_byte = digest[i];
		
		//from left to right...
		//first higher 4 bits...
		string[i*2 + 0] = (hexmap[(current_byte & 0xf0)>>4]);
		//then lower 4 bits...
		string[i*2 + 1] = (hexmap[current_byte & 0x0f]);

	}

	return string;
	

	
}

char* read_file(size_t* len, const char* filename, const char* directory){
	
	char *tmp_contents = NULL;
	std::string filename_string = std::string(filename);
	std::string directory_string = std::string(directory);

	std::string file_full_path = directory_string + "/" + filename_string;

	struct stat st = {0};
	if(stat(file_full_path.c_str(), &st) == -1) {
		return NULL;
	}

	//file exist, let's copy its contents...
	FILE* fp = fopen(file_full_path.c_str(), "rb");
	if(fp == NULL) fprintf(stderr, "Failed to open file %s\n", file_full_path.c_str());
	else {
		//let's get the file size...
		fseek(fp, 0, SEEK_END);
		*len = ftell(fp);
		rewind(fp);
		
		tmp_contents = (char*) malloc(*len);
		if(tmp_contents == NULL) {
			fprintf(stderr, "FAILED TO ALLOCATE MEMORY FOR FILE READ! EXITING OMN!\n");
			exit(-1);
		}

		size_t real_read = fread(tmp_contents, sizeof(char), *len, fp);
		if(real_read != *len) {
			fprintf(stderr, "FAILED TO READ FILE CONTENTS FULLY! EXITING OMN!\n");
			exit(-1);
		}


		fclose(fp);
	}

	return tmp_contents;
	

}

bool check_if_file_exists(const char* filepath) {

	struct stat st = {0};
	return stat(filepath, &st) != -1;

}

bool check_if_result_exists(const char* filename, const char* directory) {
	
	std::string omn_filepath = std::string(getenv("HOME")) + "/" + std::string(OMN_DIRECTORY);
	std::string this_session_filepath = omn_filepath + "/" + std::string(directory);
	std::string complete_filepath = this_session_filepath + "/" + std::string(filename);
	
	return check_if_file_exists(complete_filepath.c_str());


}

bool delete_file(const char* filename, const char* directory) {

	std::string filename_string = std::string(filename);
	std::string directory_string = std::string(directory);

	std::string file_full_path = directory_string + "/" + filename_string;

	struct stat st = {0};
	if(stat(file_full_path.c_str(), &st) == -1) {
		return true;
	}
	
	//deleting the file by unlinking
	if( unlink(file_full_path.c_str())  == 0) {
		return true;
	}
	
	return false;	

}


void save_to_file(char* data, size_t len, const char* filename, const char* directory) {

	//let's store it into a file!
	std::string filename_string = std::string(filename);
	std::string directory_string = std::string(directory);

	std::string omn_filepath = std::string(getenv("HOME")) + "/" + std::string(OMN_DIRECTORY);
	std::string this_session_filepath = omn_filepath + "/" + directory;
	std::string complete_filepath = this_session_filepath + "/" + filename;
	

	//create folders if needed
	struct stat st = {0};
	if(stat(omn_filepath.c_str(), &st) == -1) {
		mkdir(omn_filepath.c_str(), 0775);
	}
	if(stat(this_session_filepath.c_str(), &st) == -1) {
		mkdir(this_session_filepath.c_str(), 0775);
	}

	FILE* fp = fopen(complete_filepath.c_str(), "wb");
	if(fp == NULL) fprintf(stderr, "Failed to open file %s\n", complete_filepath.c_str());
	else {

		fwrite(data, sizeof(char), len, fp);
		fprintf(stdout, "Successfully printed all data inside file %s\n", complete_filepath.c_str());
		fclose(fp);
	}
}

//from libgcrypt manual.
void init_gcrypt(void) {

	if(!gcry_check_version(NEED_LIBGCRYPT_VERSION)) {
		fprintf(stderr, "libgcrypt is too old (need %s, have %s)\n", NEED_LIBGCRYPT_VERSION, gcry_check_version(NULL));
		exit(2);
	} else {
		fprintf(stderr, "libgcrypt library loaded, version %s\n", gcry_check_version(NULL));
	}

	gcry_control(GCRYCTL_DISABLE_SECMEM, 0); //no need for secure memory, we are not using libgcrypt for encryption, just hashing!!

	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

//From gpgme manual.
void init_gpgme (void)
{
/* Initialize the locale environment. */
	setlocale (LC_ALL, "");
	gpgme_check_version (NULL);
	gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
	#ifdef LC_MESSAGES
	gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
	#endif

	// check for OpenPGP support
	if(gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP) != GPG_ERR_NO_ERROR) exit(-1); //PAGE 12 GPGME manual
	// check for gpgme version and print it!
	printf("OpenPGP version %s check success! GPGme lib version: %s\n", gpgme_get_protocol_name(GPGME_PROTOCOL_OpenPGP) ,gpgme_check_version(NULL));



}


NormSessionHandle OMNCreateSession(NormInstanceHandle h_instance, NormNodeId local_NORM_ID) {



	struct timeval currentTime;
    	ProtoSystemTime(currentTime);
	
	srand(currentTime.tv_sec);  // seed random number generator

	NormSessionHandle h_session = NormCreateSession(h_instance, OMN_MULTICAST_IP, OMN_UDP_PORT, local_NORM_ID);

    	NormSetRxPortReuse(h_session, true);
    	
	NormSetMulticastLoopback(h_session, false); //do not receive from itself (watchout for NAT addresses!
       						    //They MAY be the same and this setting will DROP EVERY PACKET,
						    //EVEN FROM A VALID SOURCE WITH SAME IP BUT DIFFERENT NETWORK!)
						    //TODO: implement a option to turn it on!
    	
	return h_session;
}





char* stringify_command(Command& cmd, size_t& string_length) {
	
	//allocate space for command.
	char* tmp = NULL;
	string_length = sizeof(Command_type) + sizeof(int) + (sizeof(char)*(cmd.len));
	
	tmp = (char*) malloc(string_length);
	if(tmp == NULL) {
		fprintf(stderr, "Failed to allocate space to stringify command.\n");
		exit(-1);
	}

	//copy the command type before all.
	memcpy(tmp, &(cmd.codename), sizeof(Command_type));

	//now the opt_data length
	memcpy(tmp + sizeof(Command_type), &(cmd.len), sizeof(int));

	//copy the opt_data, if there is any!
	char* offset = tmp + sizeof(Command_type) + sizeof(int);
	
	for(int i = 0; i<cmd.len; i++) {
		char to_be_copied = cmd.opt_data[i];
		memcpy(offset + (i*sizeof(char)), &to_be_copied, sizeof(char));
	}

	
	return tmp;

}



//ALWAYS SANITIZE SV, CHECK BOUDNARIES AND SIZE (watchout for the size of the opt_data, stored after Command_type): sv length in byte MUST BE "sizeof(Command_type) + sizeof(int) + sizeof(char)*size".
void destringify_command(Command& destination, char* sv) {
	
	memcpy(&(destination.codename), sv, sizeof(Command_type));
	
	destination.len = -1;
	memcpy(&(destination.len), sv + sizeof(Command_type), sizeof(int));
	
	if(destination.len < 0) {
		fprintf(stderr, "Failed to destringify command: invalid size.\n");
		exit(-1);
	}

	if(destination.len > 0) {
		destination.opt_data = (char*) malloc(destination.len);

		if(destination.opt_data == NULL) {
			fprintf(stderr, "Failed to allocate space for optional data of command.\n");
			exit(-1);
		}
		
		char* offset = sv + sizeof(Command_type) + sizeof(int);
		//copy the command type before all.
		memcpy(destination.opt_data, offset, destination.len);

	} else {
		destination.opt_data = NULL;
	}


}














//ALWAYS SANITIZE SV, CHECK BOUDNARIES AND SIZE (watchout for the size of the opt_data, stored after Command_type): sv length in byte MUST BE "sizeof(Command_type) + sizeof(int) + sizeof(char)*size".
void destringify_response(Response& destination, char* sv) {
	
	memcpy(&(destination.codename), sv, sizeof(Response_type));
	
	destination.len = -1;
	memcpy(&(destination.len), sv + sizeof(Response_type), sizeof(int));
	
	if(destination.len < 0) {
		fprintf(stderr, "Failed to destringify response: invalid size.\n");
		exit(-1);
	}

	if(destination.len > 0) {
		destination.opt_data = (char*) malloc(destination.len);

		if(destination.opt_data == NULL) {
			fprintf(stderr, "Failed to allocate space for optional data of response.\n");
			exit(-1);
		}
		
		char* offset = sv + sizeof(Response_type) + sizeof(int);
		//copy the reponse type before all.
		memcpy(destination.opt_data, offset, destination.len);

	} else {
		destination.opt_data = NULL;
	}


}







char* stringify_response(Response& rsp, size_t& string_length) {

	//allocate space for command.
	char* tmp = NULL;
	string_length = sizeof(Response_type) + sizeof(int) + (sizeof(char)*(rsp.len));
	
	tmp = (char*) malloc(string_length);
	if(tmp == NULL) {
		fprintf(stderr, "Failed to allocate space to stringify response.\n");
		exit(-1);
	}

	//copy the response type before all.
	memcpy(tmp, &(rsp.codename), sizeof(Response_type));

	//now the opt_data length
	memcpy(tmp + sizeof(Response_type), &(rsp.len), sizeof(int));

	//copy the opt_data, if there is any!
	char* offset = tmp + sizeof(Response_type) + sizeof(int);
	
	for(int i = 0; i<rsp.len; i++) {
		char to_be_copied = rsp.opt_data[i];
		memcpy(offset + (i*sizeof(char)), &to_be_copied, sizeof(char));
	}

	
	return tmp;

}














void opt_data_SEND_FILE_get(Command cmd, opt_data_SEND_FILE& dst) {

	//1) CMD must be LAN_NAME_LENGTH + RESULT_NAME_LENGTH + SHA256_READABLE_LENGTH bytes long.
	if(cmd.len != sizeof(opt_data_SEND_FILE)) {
		fprintf(stderr, "Command is not a valid SEND_FILE command! Can't get opt_data!" );
		exit(-1);
	}

	//2) copy all fields...
	memcpy(dst.lan_name_of_executor, cmd.opt_data, LAN_NAME_LENGTH);	

	memcpy(dst.directory, cmd.opt_data + LAN_NAME_LENGTH, RESULT_NAME_LENGTH);
	dst.directory[RESULT_NAME_LENGTH - 1] = '\0';
	
	memcpy(dst.hash_filename, cmd.opt_data + LAN_NAME_LENGTH + RESULT_NAME_LENGTH, SHA256_READABLE_LENGTH);
	dst.hash_filename[SHA256_READABLE_LENGTH - 1] = '\0';

}






//this is a callback function that GPGME calls if a key interact operation is on-going (GPGME manual pdf, page 80)
//It will trust the keys to the ULTIMATE trust level.
gpgme_error_t trust_interaction_func_automatic(void* handle, const char* status, const char* args, int fd) {
	//empty string --> EOF
	//fd is -1 for normal status messages
	//status indicates a command, rather then a status message, the response to the command should be written to fd.
	//handle is provided by the user at start of operation (if he wants to pass any object)
	gpgme_data_t out = (gpgme_data_t) handle;
	
	//fprintf(stdout, "Response from crypto engine:\n");
	//print_result_to_screen(out);
		
	const char* response = NULL;
	static bool next_time_quit = false;

	//OK, the interaction is just a finite state machine. We get statuses and we respond to them.
	//fprintf(stdout, "-------------\nStatus: %s\nArgs: %s\n--------------\n", status, args);
		
	

	//if file descriptor is not -1, then it is a normal status message.
	if(fd >= 0) {
		if(!strcmp(args, "keyedit.prompt") && !strcmp(status, "GET_LINE")) {
			if(!next_time_quit) {
				response = "trust"; //static string, will have a valid memory position at runtime.
				next_time_quit = true;
			} else {
				response = "quit";
				next_time_quit = false;
			}
		} else if(!strcmp(args, "edit_ownertrust.value") && !strcmp(status, "GET_LINE")) {
			response = "5";
		} else if(!strcmp(args, "edit_ownertrust.set_ultimate.okay") && !strcmp(status, "GET_BOOL") ) {
			response = "y";
		} else {
			fprintf(stdout, "Something went wrong... Unexpected args in GPG edit-key finite state machine.\n Status: %s\nArgs: %s\n", status, args);
			exit(-1);
		}
	}

	//fprintf(stdout, "resp: %s\n", response);
	
	if(response != NULL) {
		gpgme_io_writen(fd, response, strlen(response));
	}
	gpgme_io_writen(fd, "\n", 1); //press "enter" virtually, always.
	return 0; //no errors!

}

//this is a callback function that GPGME calls if a key interact operation is on-going (GPGME manual pdf, page 80)
//It will trust the keys to the ULTIMATE trust level.
//YOU ARE THE ONE ENTERING THE COMMANDS.
//USED ONLY FOR DEBUG PURPOSES, TO LEARN HOW THE EDIT-KEY GPG FINITE STATE MACHINE WORKS!
gpgme_error_t trust_interaction_func_interactive(void* handle, const char* status, const char* args, int fd) {
	//empty string --> EOF
	//fd is -1 for normal status messages
	//status indicates a command, rather then a status message, the response to the command should be written to fd.
	//handle is provided by the user at start of operation (if he wants to pass any object)
	gpgme_data_t out = (gpgme_data_t) handle;
	
	fprintf(stdout, "Response from crypto engine:\n");
	print_result_to_screen(out);
		
	char response[256] = {0};

	//OK, the interaction is just a finite state machine. We get statuses and we respond to them.
	fprintf(stdout, "-------------\nStatus: %s\nArgs: %s\n--------------\n", status, args);
		
	

	//if file descriptor is not -1, then it is a normal status message.
	if(fd >= 0) {
		fprintf(stdout, "Enter response... ");
		scanf("%s", response);
	}

	if(response) {
		gpgme_io_writen(fd, response, strlen(response));
	}
	gpgme_io_writen(fd, "\n", 1); //press "enter" virtually, always.
	return 0; //no errors!

}



void print_result_to_screen(gpgme_data_t out) {
	char* tmp;

	//read the size of out. From start to end. Then reset the cursor.
	gpgme_data_seek(out, 0, SEEK_SET);
	size_t chars_to_be_read = gpgme_data_seek(out, 0, SEEK_END);
	gpgme_data_seek(out, 0, SEEK_SET);

	//let's read it all inside stdout.
	if(chars_to_be_read > 0) {
		tmp = (char*) malloc(chars_to_be_read);
	
		if(tmp == NULL) {
			fprintf(stderr, "Failed to allocate space to read crypto engine response.\n");
			exit(-1);
		}

		if(gpgme_data_read(out, tmp, chars_to_be_read) == -1) {
			fprintf(stderr, "Failed to read crypto engine response.\n");
			exit(-1);
		}

		fwrite(tmp, chars_to_be_read, 1, stdout);
	}

}



