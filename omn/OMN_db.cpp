
#include "OMN_db.h"



void OMN_db_status::add_LANNAME_to_list_of_result_suppliers(string result, string hash, string lan_name) {
	
	//let's just add it...
	(((*this)[result])[hash]).insert(lan_name);

}


bool OMN_db_status::get_OMN_db_status() {
	//does the file exist? If it doesn't exist it means it is the first time we are running OMN in this pc!
	std::string omn_db_filepath = std::string(getenv("HOME")) + "/" + std::string(OMN_DIRECTORY) + "/" + std::string(DB_CURRENT_STATE_FILENAME);
	struct stat st = {0};
        if(stat(omn_db_filepath.c_str(), &st) != -1) {
		//the file exists! We can try to retrieve information...
		bool we_retrieved_info = false;

		//open the file and fill up the map!
		FILE* fp = NULL;
		fp = fopen( omn_db_filepath.c_str() , "rb");
		

		struct tm * time_of_last_modify = localtime(&st.st_ctime);
		this->last_modify = string(asctime(time_of_last_modify));

		if(fp == NULL) {
			fprintf(stderr, "Error! Couldn't open client result list's file\n");
			exit(-1);
		}
		
		//get the file size.
		fseek(fp, 0, SEEK_END);
		size_t file_size = ftell(fp);
		rewind(fp);

		if(file_size == 0) {
			fprintf(stdout, "OMN db status checked: no status avaliable. Time for an update?\n");
		} else {
			
			//let's sanitize the file.
			bool sanitization_completed = sanitize_OMN_db_file(fp, file_size);
			if(sanitization_completed) {
				rewind(fp);
				we_retrieved_info = initialize_OMN_db_status(fp, file_size);
			}
		}
		
		fclose(fp);
		return we_retrieved_info;

	} else {
		fprintf(stdout, "OMN db status checked: no status avaliable. Time for an update?\n");
		this->last_modify = string("OMN DB status file does not exist.");
		//the file doesn't exist. OMN_db_status is empty!
		return false;
	}

	return false;
	
	

}


bool OMN_db_status::sanitize_OMN_db_file(FILE* fp, size_t full_size_of_file) {

	if(full_size_of_file == 0) return true;
	else {
		//try to see if there are at least RESULT_NAME_LENGTH + sizeof(int) bytes.
		if(full_size_of_file < RESULT_NAME_LENGTH + sizeof(int)) return false;
		
		rewind(fp);
		//we can initialize the check algorythym. If we reach end of file without problems, we can return true.
		while(ftell(fp) != full_size_of_file) {
			//skip the RESULT_NAME_LENGTH and read the number of hashes associated to it.
			if(fseek(fp, RESULT_NAME_LENGTH, SEEK_CUR) != 0) 
				return false;
			int num_of_hashes;
			if(fread(&num_of_hashes, sizeof(int), 1, fp) != 1) 
				return false;
			
			if(num_of_hashes < 0 || num_of_hashes > max_num_of_nodes) 
				return false;

			//check that the number of hashes doesn't cause a read out of boundaries.
			//let's try to read each HASH and their associated set of possible suppliers.
			for(int i = 0; i < num_of_hashes; i++) {
				//try to skip the READABLE HASH string.
				if(fseek(fp, SHA256_READABLE_LENGTH, SEEK_CUR) != 0) 
					return false;
				//try to read the size of the stringified set of LAN_NAMES strings.
				size_t stringified_set_length = 0;
				if(fread(&stringified_set_length, sizeof(size_t), 1, fp) != 1)
					return false;
				//is it valid?
				if(stringified_set_length < 0) return false;
				//shall be aligned to LAN_NAME_LENGTH.
				if(stringified_set_length % LAN_NAME_LENGTH != 0) return false;
				//try to skip the stringified set.
				if(fseek(fp, stringified_set_length, SEEK_CUR) != 0)
					return false;
				
				//next hash.
				
			}
			

		}
	
		return true;
	}

	return false;
}

bool OMN_db_status::initialize_OMN_db_status(FILE* fp, size_t full_size_of_file) {
	//sanitization was already done, we can trust the size_t and integers.
	
	//structure of (a non null) OMN db file, for reference!
	// ALWAYS PRESENT >>>  RESULT_NAME (256 char) | num_of_hashes (int, max 200) | (continues below...)
	// OPTIONAL 	  >>>  HASH (256 char) | stringified_set_length (size_t bytes) | stringified_set_of_lan_who_got_file_with_hash_HASH |
	// REPEATING...   >>>  HASH ... | RESULT_NAME | ...
	char buf[RESULT_NAME_LENGTH + sizeof(int)];
	while(fread(buf, sizeof(char), RESULT_NAME_LENGTH + sizeof(int), fp) == (RESULT_NAME_LENGTH + sizeof(int))) { //continue till we can read the RESULT_NAME and num_of_hashes in it!
		//convert...
		char result_name[RESULT_NAME_LENGTH] = "";
		memcpy(&result_name, buf, RESULT_NAME_LENGTH - 1);
		string result_name_str = string(result_name);

		int num_of_hashes;
		memcpy(&num_of_hashes, buf + RESULT_NAME_LENGTH, sizeof(int));
		
		//create the first-level entry for this result name. Start with an empty second-level map (hash_of_file -> possible_file_supplier_LANs) entry.
		(*this)[result_name_str] = map<string, set<string>>();
		
		//now let's add each second-level map's entry.
		for(int i = 0; i < num_of_hashes; i++) {
			//read the hash
			char current_hash[SHA256_READABLE_LENGTH] = "";
			fread(current_hash, sizeof(char), SHA256_READABLE_LENGTH, fp);
			current_hash[SHA256_READABLE_LENGTH - 1] = '\0';

			//read the stringified set length (CAN BE ZERO!!! ALREADY SANITIZED).
			size_t stringified_set_length = 0;
			fread(&stringified_set_length, sizeof(size_t), 1, fp);

			//add the second-level map's entry. START WITH AN EMPTY SET!
			((*this)[result_name_str])[string(current_hash)] = set<string>();
			
			if(stringified_set_length != 0) { //SANITIZATION ALREADY CHECKED THERE IS AT LEAST SPACE FOR 1 SHA256_READABLE_LENGTH!
				//read the stringified set AND convert it to object.
				char* tmp_stringified_set = (char*) malloc(stringified_set_length);
				if(tmp_stringified_set == NULL) {
					fprintf(stderr, "Error! Failed to allocate space to temporarily store stringified set of LANs\n");
					exit(-1);	
				}
				fread(tmp_stringified_set, sizeof(char), stringified_set_length, fp);

				destringify_set_of_lanNames(((*this)[result_name_str])[string(current_hash)], tmp_stringified_set, stringified_set_length);

				free(tmp_stringified_set);
			}
		}

	}

	return true;
}

void OMN_db_status::destringify_set_of_lanNames(set<string>& s, char* buff, size_t& total_size_of_input_buffer) {
	
	//sanitized buff don't need to check for remainder problems, we can trust the total_size_of_input_buffer to be aligned to LAN_NAME_LENGTH
	//and not 0.
	int num_of_lan_names = total_size_of_input_buffer / LAN_NAME_LENGTH;
	
	//copy each LAN name inside set.
	off_t off = 0;
	for(int i = 0; i < num_of_lan_names; i++) {

		char tmp_lan_name[LAN_NAME_LENGTH] = "";
		memcpy(tmp_lan_name, buff + off, LAN_NAME_LENGTH - 1);
		
		s.insert(string(tmp_lan_name));
		
		off += LAN_NAME_LENGTH;
		
	}
	


}


char* OMN_db_status::stringify_set_of_lanNames(const set<string>& s, size_t& size_allocated) {
	
	size_allocated = sizeof(char) * LAN_NAME_LENGTH * s.size();
	char * tmp = (char*) malloc(size_allocated);
	
	if(tmp == NULL) {
		fprintf(stderr, "ERROR: Could not allocate space for stringified version of lan names set.\n");
		exit(-1);
	}
	
	//copy each LAN name inside memory.
	off_t off = 0;
	for(string str: s) {
		if(str.size() <= LAN_NAME_LENGTH - 1) {
			//gotta copy it into a static-size vector! THE NAME COULD BE SHORTER THAN LAN_NAME_LENGTH
			char tmp_str[LAN_NAME_LENGTH] = "";
			memcpy(tmp_str, str.c_str(), str.size());

			memcpy(tmp + off, tmp_str, LAN_NAME_LENGTH);
			off += LAN_NAME_LENGTH;
		} else {
			fprintf(stderr, "ERROR: Lan name's size is incorrect. Can't stringify lan name during set stringification.\n");
		}
	}
	
	
	return tmp;

}


void OMN_db_status::save_OMN_db_status() {
	FILE* fp = NULL;
	std::string omn_db_filepath = std::string(getenv("HOME")) + "/" + std::string(OMN_DIRECTORY) + "/" + std::string(DB_CURRENT_STATE_FILENAME);
	fp = fopen( omn_db_filepath.c_str() , "wb");
	
	if(fp == NULL) {
		fprintf(stderr, "Error! Couldn't open client result list's file\n");
		exit(-1);
	}
	
	
	//now we save the results like this:
	// RESULT_NAME (256 char) | num_of_hashes (int, max 200) | HASH (256 char) | stringified_set_length (size_t bytes) | stringified_set_of_lan_who_got_file_with_hash_HASH
	for(const pair<string, map<string,set<string>>>& lvl1_el: *this) {
		//write the string.
		if(lvl1_el.first.size() <= RESULT_NAME_LENGTH-1) {
			//gotta copy it into a static-size vector! THE NAME COULD BE SHORTER THAN RESULT_NAME_LENGTH
			char tmp[RESULT_NAME_LENGTH] = "";
			memcpy(tmp, lvl1_el.first.c_str(), lvl1_el.first.size());
			fwrite(tmp, sizeof(char), RESULT_NAME_LENGTH, fp);
		}
		else {
			fprintf(stderr, "WRONG LENGTH FOR RESULT NAME! USING PLACEHOLDER!\n");
			char placeholder[RESULT_NAME_LENGTH] = "INVALID_RESULT_NAME";
			fwrite(placeholder, sizeof(char), RESULT_NAME_LENGTH, fp);
		}

		//write the number of hashes for resultname.
		int num_of_hashes = lvl1_el.second.size() <= max_num_of_nodes && lvl1_el.second.size() >= 0 ? lvl1_el.second.size() : -1;
		
		if(num_of_hashes == -1) {
			fprintf(stderr, "Wrong result number, putting it to null!\n");
			num_of_hashes = 0;
		}
		
		fwrite(&num_of_hashes, sizeof(int), 1, fp);
		
		if(num_of_hashes > 0) {	
			//now write each entry of the map "hash -> set of LANs who got that hash".
			//NOTE: if the num_of_hashes is 0, then there will NOT be any | HASH | stringified_set_length | stringified_set_of_lan_who_got_file_with_hash_HASH part after it!!!!
			for(const pair<string, set<string>> lvl2_el: lvl1_el.second) {
				//write the hash
				if(lvl2_el.first.size() == SHA256_READABLE_LENGTH -1)
					fwrite(lvl2_el.first.c_str(), sizeof(char), SHA256_READABLE_LENGTH, fp);
				else {
					fprintf(stderr, "WRONG LENGTH FOR SHA256 READABLE HASH! USING PLACEHOLDER!\n");
					char placeholder[SHA256_READABLE_LENGTH] = "INVALID_HASH";
					fwrite(placeholder, sizeof(char), SHA256_READABLE_LENGTH, fp);
				}
				
				//stringify the set.
				size_t allocated_space = 0;
				char* stringified_set = stringify_set_of_lanNames(lvl2_el.second, allocated_space);
				
				//note: if there are no clients who can support the hash "HASH", then it is simply added to the file as an empty list.
				if(stringified_set != NULL && allocated_space > 0) {
					//write the stringified set length
					fwrite(&allocated_space, sizeof(size_t), 1, fp);
					
					//write the stringified set
					fwrite(stringified_set, sizeof(char), allocated_space, fp);
					
					free(stringified_set);
				} else {
					fprintf(stderr, "Stringified set of LANs has invalid size. Writing zero instead.\n");
					allocated_space = 0;
					//write the stringified set length
					fwrite(&allocated_space, sizeof(size_t), 1, fp);

					if(stringified_set != NULL) free(stringified_set);
				}

			}

		}

	}

	fclose(fp);


}









bool OMN_db_status::test_class() {

	OMN_db_status m1 = OMN_db_status(3);
	map<string, set<string>> m11;
	map<string, set<string>> m12; //empty, no hashes, should still compare in file.

	OMN_db_status m2 = OMN_db_status(3);
	map<string, set<string>> m21;
	map<string, set<string>> m22; //empty, no hashes, should still compare in file.

	set<string> s1_1 = {"LAN1", "LAN2"};
	set<string> s1_2 = {"LAN3", "LAN2", "LAN1"};


	set<string> s2_1 = {"LAN1", "LAN2"};
	set<string> s2_2 = {"LAN3", "LAN2", "LAN1"};

	//2 hashes, got different suppliers.
	m11["3b33a2e33ef8e4da3cfed0c4a299c7874658fe4a9e230a69d91b0c2174c6dd36"] = s1_1;
	m11["3b33a2e33ef8e4da3cfed0c4a299c7874658fe4a9e230a69d91b0c2174c6dd37"] = s1_2;

	//copy
	m21["3b33a2e33ef8e4da3cfed0c4a299c7874658fe4a9e230a69d91b0c2174c6dd36"] = s2_1;
	m21["3b33a2e33ef8e4da3cfed0c4a299c7874658fe4a9e230a69d91b0c2174c6dd37"] = s2_2;


	//2 scan result.
	m1["nmap_scan_0"] = m11;
	m1["nmap_scan_1"] = m12;
	
	m1.add_LANNAME_to_list_of_result_suppliers(string("nmap_scan_0"), string("3b33a2e33ef8e4da3cfed0c4a299c7874658fe4a9e230a69d91b0c2174c6dd37"), string("LAN4"));

	m2["nmap_scan_0"] = m21;
	m2["nmap_scan_1"] = m22;
	
	m2.add_LANNAME_to_list_of_result_suppliers(string("nmap_scan_0"), string("3b33a2e33ef8e4da3cfed0c4a299c7874658fe4a9e230a69d91b0c2174c6dd37"), string("LAN4"));

	//test ==
	if(!(m1 == m2)) return false;
	cout << "All ok! == Works" << endl;

	OMN_db_status m3 = OMN_db_status(3);

	//test saving and loading.
	m1.save_OMN_db_status();
	m3.get_OMN_db_status();

	if(!(m1 == m3)) return false;
	
	cout << "All ok! file saving Works" << endl;

	return true;
}



void OMN_db_status::update_OMN_db_status_by_OMN_slave_db_status(OMN_slave_db_status sDBstat) {
	
	//sDBstat is just a bunch of Resultname -> hashes mappings.

	//we update the OMN_db_status (master's) by simply iterating over each key of the slave's DB status (results)...
	for(const pair<string, set<string>>& p: sDBstat) {
		//and over each element of the slave's DB status (hashes)...
		for(const string str: p.second) {
			//and try to add the owner of sDBstat (LAN NAME) to each set of supplier lans. 
			//If it is already present in the set, the owner will not be added a second time
			//if it is not present in the set, or we don't have the result, or we don't have the hash, then they are all added to the master's OMN_db_status.
			(((*this)[p.first])[str]).insert(sDBstat.owner);
		}
	}

}





bool OMN_slave_db_status::sanitize_stringified_slave_db_status(char* stringified_map, size_t total_allocated_size, int max_num_of_nodes, int& num_of_elements_found) {

	bool sanitization_done = false;
	num_of_elements_found = 0;

	if(total_allocated_size == 0) {
		sanitization_done = true;
	} else if(total_allocated_size < RESULT_NAME_LENGTH + sizeof(int) ){ //we need at least this space, if total_allocated_size isn't zero.
		fprintf(stderr, "Invalid total allocated size (%ld bytes) for stringified map of results.\n", total_allocated_size);
		sanitization_done = false;
	} else {
		//if we are here, we can at least prime the sanitization process with a first opt_data_RESULT_LIST_element!
		size_t off = 0;
		
		do{
			//if we are inside here, it's because we can still continue
			//1. Can we read at least RESULT_NAME_LENGTH + sizeof(int) bytes, without going out of buffer boundaries?
			//   or causing a overflow in the addition process?
			size_t try_off = 0;
			if(__builtin_uaddl_overflow(off, RESULT_NAME_LENGTH + sizeof(int), &try_off )) {
				fprintf(stderr, "Overflow in offset addition while trying to sanitize a results file list.\n");
				break;
			}
			if(try_off > total_allocated_size) {
				//if this control fails, this means the buffer is malformed
				//and isn't aligned to a good opt_data_RESULT_LIST_element.
				//TO BE DECLARED CORRECT, A BUFFER MUST CONTAIN opt_data_RESULT_LIST_element ENTIRELY!!!
				fprintf(stderr, "Just prevented a buffer overflow while trying to sanitize a results file list.\n");
				break;
			}
			//seems like, if we still inside the cycle, the answer is yes! Let's extract just the int.
			int supposed_number_of_elements = 0;
		       	memcpy(&supposed_number_of_elements, (stringified_map + try_off) - sizeof(int), sizeof(int));
			//2.we need to check if the int is positive and that it does not go out of boundaries 
			//(max number of hashes is the same as max number of OMN slaves per active session)...
			if(supposed_number_of_elements < 0 || supposed_number_of_elements > max_num_of_nodes) {
				fprintf(stderr, "Invalid number of elements (%d) discovered while trying to sanitize a result file list!\n", supposed_number_of_elements);
				break;	
			}
			//3. if it is positive, will the remaining  allocated buffer space suffice to contain 
			//   ALL the supposed_number_of_elements SHA256 HUMAN-READABLE hashes???
			size_t try_off2 = 0;
			size_t space_needed_for_supposed_hashes_elements = 0;
			if(__builtin_umull_overflow(supposed_number_of_elements, SHA256_READABLE_LENGTH, &space_needed_for_supposed_hashes_elements)) {
				fprintf(stderr, "Overflow while trying to discover the space needed for %d hashes\n", supposed_number_of_elements);
				break;
			}
			if(__builtin_uaddl_overflow(try_off, space_needed_for_supposed_hashes_elements, &try_off2 )) {
				fprintf(stderr, "Overflow in offset addition while trying to see if %d hashes can really be contained inside the buffer undergoing sanitization process.\n", supposed_number_of_elements);
				break;
			}
			if(try_off2 > total_allocated_size) {
				fprintf(stderr, "Just prevented a buffer overflow while trying to see if %d hashes can really be contained inside the buffer undergoing sanitization process.\n", supposed_number_of_elements);
				break;
			}
			//seems like the supposed number of elements is valid... Ok... onto the next opt_data_RESULT_LIST_element...
			off = try_off2; //new offset will be the last valid offset...
			num_of_elements_found++;

			//only way to declare a buffer valid for map destringification is for offset to arrive just at the
			//"finish line", just at the last byte, the end of the buffer.
			if(off == total_allocated_size) sanitization_done = true;

		}while(!sanitization_done); //continue till sanitization has not finished.

	}


	return sanitization_done;

}





void OMN_slave_db_status::retrieve_slave_db_status() {
	
	string omn_filepath = string(getenv("HOME")) + "/" + string(OMN_DIRECTORY);
	
	//open OMN directory
	DIR* dirp = opendir(omn_filepath.c_str());
	
	if(dirp == NULL) {
		fprintf(stderr, "Failed to retrieve list of scan results, reason: couldn't open OMN directory.\n");
		exit(-1);
	}

	struct dirent* directory_entry = NULL;
	directory_entry = readdir(dirp);
	
	//cycle each scan folder (each scan/results folder can contain max_num_of_nodes max encrypted results from other slaves...)
	while(directory_entry != NULL) {
		string current_result_name = string(directory_entry->d_name);
		//The omn folder can contain only folders (result ones only!) and some configuration files.
		//We will select only the folders (DT_DIR, man 3 reddir), and among them all except the "special" ones
		//this folder "." and top folder ".."
		if(current_result_name != "." && current_result_name != ".." && directory_entry->d_type == DT_DIR) {

			string full_result_path = omn_filepath + "/" + current_result_name;
			//cycle each encrypted result filename...

			DIR* dirp_2 = opendir(full_result_path.c_str());
		
			struct dirent* encrypted_result_entry = NULL;
			encrypted_result_entry = readdir(dirp_2);
			
			set<string> list_of_hashes;
			
			while(encrypted_result_entry != NULL) {
				//the encrypted results are saved with a filename indicating their SHA256 hashes.
				string current_hash = string(encrypted_result_entry->d_name);
				
				//TODO: remember to not pick up the hidden file!!!
				//Use a regex to not pick up hidden files (they have a dot at the start of the filename)
				if(current_hash.size() == (SHA256_READABLE_LENGTH - 1))
					list_of_hashes.insert(current_hash);

				encrypted_result_entry = readdir(dirp_2);

			}
			//let's close the results directory, we don't need it anymore
			closedir(dirp_2);

			//add the list of hashes to the map, if the folder isn't empty!
			if(list_of_hashes.size() != 0)
				(*this)[current_result_name] = list_of_hashes;

		}

		//next scan results directory (full of results, we hope)
		directory_entry = readdir(dirp);

	}
	
	//let's close OMN's directory too.
	closedir(dirp);


}






//this will be called by slaves to construct their opt_data of response to SEND_RESULT_LIST command.
char* OMN_slave_db_status::stringify_slave_db_status(size_t& allocated_space) {
	char* str = NULL;
	allocated_space = 0;
	off_t off = 0;

	for(const pair<string, set<string>>& kv: (*this)) {
		//each key->value pair is just an opt_data_RESULT_LIST_element.
		opt_data_RESULT_LIST_element tmp_e = OMN_slave_db_status::create_opt_data_RESULT_LIST_element_from_map_pair_string_setstring(kv);
		//to create a stringified version of the map, we just concatenate 
		//each opt_data_RESULT_LIST_element in the buffer to be returned.
		
		if(allocated_space == 0) {
			allocated_space = RESULT_NAME_LENGTH + sizeof(int) + SHA256_READABLE_LENGTH*tmp_e.num_files_in_this_directory;
			str = (char*) malloc(allocated_space);
			if(str == NULL) {
				fprintf(stderr, "Failed to allocate space for result list element. Aborting!\n");
				exit(-1);
			}
			off = 0;
		} else {
//			off += allocated_space; //starting from the first byte (to be) allocated this round... 
			allocated_space += RESULT_NAME_LENGTH + sizeof(int) + SHA256_READABLE_LENGTH*tmp_e.num_files_in_this_directory;
			str = (char*) realloc(str, allocated_space);
			if(str == NULL) {
				fprintf(stderr, "Failed to reallocate space for another result list element. Aborting!\n");
				exit(-1);
			}
		}
		
		//now let's just copy it...
		memcpy(str + off, tmp_e.result_directory, RESULT_NAME_LENGTH);
		off += RESULT_NAME_LENGTH;
		memcpy(str + off, &(tmp_e.num_files_in_this_directory), sizeof(int));
		off += sizeof(int);
		memcpy(str + off, tmp_e.file_list, SHA256_READABLE_LENGTH*tmp_e.num_files_in_this_directory);
		off += SHA256_READABLE_LENGTH*tmp_e.num_files_in_this_directory;

		free(tmp_e.file_list);
	}


	return str; //returns NULL if map was empty!

}












	
bool OMN_slave_db_status::destringify_slave_db_status(char * stringified_map, int max_num_of_nodes, size_t total_allocated_size) {
	//first, check that all num_files_in_this_directory integers will not give buffer overflow problems.
	//	 check that the content actually corresponds to total_allocated_size (total_allocated_size should be aligned to
	//	 	RESULT_NAME_LENGTH, sizeof(int), num_files_in_this_directory*SHA256_READABLE_LENGTH.
	//I.E.   SANITIZE THE STRINGIFIED MAP!
	int num_of_elements_found = 0;
	bool all_ok = OMN_slave_db_status::sanitize_stringified_slave_db_status(stringified_map, total_allocated_size, max_num_of_nodes, num_of_elements_found);

	if(all_ok) {
		//we destringify it!
		off_t off = 0;
		for(int i = 0; i < num_of_elements_found; i++) {
			//we first create an opt_data_RESULT_LIST_element from the current offset...
			opt_data_RESULT_LIST_element el = get_opt_data_RESULT_LIST_element_from_offset(stringified_map + off);
			//then we add it to the map.
			(*this).add_opt_data_RESULT_LIST_element(el);

			free(el.file_list);
			off += RESULT_NAME_LENGTH + sizeof(int) + (el.num_files_in_this_directory*SHA256_READABLE_LENGTH);
		}
	}



	return all_ok;


}





void OMN_slave_db_status::add_opt_data_RESULT_LIST_element(opt_data_RESULT_LIST_element e) {

	set<string> v;

	off_t off = 0;
	for(int i = 0; i < e.num_files_in_this_directory; i++) {
		char temp[SHA256_READABLE_LENGTH] = {0};
		memcpy(temp, e.file_list + off, SHA256_READABLE_LENGTH - 1); //omit last character, null terminator...

		v.insert(string(temp));

		off += SHA256_READABLE_LENGTH;

	}

	(*this)[string(e.result_directory)] = v;


	
}



//does not sanitize.
opt_data_RESULT_LIST_element OMN_slave_db_status::get_opt_data_RESULT_LIST_element_from_offset(char* ptr) {
	opt_data_RESULT_LIST_element e;

	memcpy(e.result_directory, ptr, RESULT_NAME_LENGTH);
	e.result_directory[RESULT_NAME_LENGTH - 1] = '\0';

	memcpy(&(e.num_files_in_this_directory), ptr + RESULT_NAME_LENGTH, sizeof(int));
	//first malloc.
	e.file_list = NULL;
	e.file_list = (char*) malloc(e.num_files_in_this_directory * SHA256_READABLE_LENGTH);
	if(e.file_list == NULL) {
		fprintf(stderr, "Failed to allocate space for hashes list for result list element\n");
		exit(-1);
	}
	memcpy(e.file_list, ptr + RESULT_NAME_LENGTH + sizeof(int), e.num_files_in_this_directory * SHA256_READABLE_LENGTH );
	
	return e;
}




char* OMN_slave_db_status::stringify_list_of_hashes(const set<string>& v) {
	//just take each element of v and memcpy it inside a heap buffer.
	char * buf = (char*) malloc(v.size() * SHA256_READABLE_LENGTH);

	if(buf == NULL) {
		fprintf(stderr, "Failed to allocate buffer to contain stringified list of hashes. Aborting!\n");
		exit(-1);
	}

	off_t off = 0;	
	for(const string& s: v) {
		if(s.size() != (SHA256_READABLE_LENGTH - 1)) {
			fprintf(stderr, "Incorrect size for readable sha256 hash. ABORTING!\n");
			exit(-1);
		}

		memcpy(buf + off, s.c_str(), SHA256_READABLE_LENGTH);

		off += SHA256_READABLE_LENGTH;
	}
	
	return buf;

}



opt_data_RESULT_LIST_element OMN_slave_db_status::create_opt_data_RESULT_LIST_element_from_map_pair_string_setstring(const pair<string, set<string>>& p) {
	opt_data_RESULT_LIST_element e;
	
	//Writing result name...
	if(p.first.size() > RESULT_NAME_LENGTH - 1) {
		fprintf(stderr, "Malformed result name found inside map object. Aborting!\n");
		exit(-1);
	}
	
	char tmp_result_name[RESULT_NAME_LENGTH] = "";
	memcpy(tmp_result_name, p.first.c_str(), p.first.size());

	memcpy(e.result_directory, tmp_result_name, RESULT_NAME_LENGTH);

	e.num_files_in_this_directory = p.second.size();
	//Now we need to stringify the list of hashes...
	e.file_list = stringify_list_of_hashes(p.second);

	return e;
}


