
//OMN masters can locally save a "status" of the distributed OMN database.
//This status can be (and is) represented by a 2 levels hashmap -->
//	first level  >>>  string (scan/result name, OMN saves all results inside a homonym directory) -> map (see second level)
//	second level >>>  string (hash of a specific OMN client's result, stored under "scan/result name" directory) -> set of strings (lan names of those OMN clients who have a copy of the result!)
//
//when OMN masters terminate, if the state of the map has changed, the file is changed too accordingly.

#ifndef OMN_DB_H
#define OMN_DB_H
#include "OMN_common.h"

using namespace std;

class OMN_slave_db_status : public map<string, set<string>> {
	
	public:
		string owner; //the slave who has this status.

		//scans OMN folder for all results, and builds a map of result_name -> list_of_hashes.
		void retrieve_slave_db_status();

		//this will be called by slaves to construct their opt_data of response to SEND_RESULT_LIST command.
		char* stringify_slave_db_status(size_t& allocated_space);


		//returns true if map contains a valid destrigified map.
		//THIS FUNCTION DOES NOT DEALLOCATE STRINGIFIED_MAP!!!
		//Used mainly by masters.
		bool destringify_slave_db_status(char * stringified_map, int max_num_of_nodes, size_t total_allocated_size);

	private:
		//used mainly by masters
		static bool sanitize_stringified_slave_db_status(char* stringified_map, size_t total_allocated_size, int max_num_of_nodes, int& num_of_elements_found);
		static opt_data_RESULT_LIST_element get_opt_data_RESULT_LIST_element_from_offset(char* ptr);
		
		//used mainly by slaves
		static char* stringify_list_of_hashes(const set<string>& v);
		static opt_data_RESULT_LIST_element create_opt_data_RESULT_LIST_element_from_map_pair_string_setstring(const pair<string, set<string>>& p);
		void add_opt_data_RESULT_LIST_element(opt_data_RESULT_LIST_element e);

};

class OMN_db_status : public map<string, map<string, set<string>>> {
	
	public:
		string last_modify;
		int max_num_of_nodes; //used for sanitization purposes
		
		OMN_db_status(int max_num_of_nodes) {
			this->max_num_of_nodes = max_num_of_nodes;
		}

		//gets OMN distributed database status from file.
		bool get_OMN_db_status();

		//saves OMN distributed database status to file.
		// RESULT_NAME (256 char) | num_of_hashes (int, max 200) | HASH (256 char) | stringified_set_length (size_t bytes) | stringified_set_of_lan_who_got_file_with_hash_HASH | HASH ... | RESULT_NAME | ...
		void save_OMN_db_status();

		//adds (if not present) the LAN NAME string to the set of suppliers for a specific hash.
		void add_LANNAME_to_list_of_result_suppliers(string result, string hash, string lan_name);

		//processes the map of resultname -> hashes list, updating OMN's DB status. 
		//Adds "lan_name" of sDBstat to the set of lan names who have a copy of a specific OMN client's result (marked by a specific hash), 
		//which is stored under the "resultname" directory.
		void update_OMN_db_status_by_OMN_slave_db_status(OMN_slave_db_status sDBstat);
	
		//little test to see if it works	
		static bool test_class();
	private:

		char* stringify_set_of_lanNames(const set<string>& s, size_t& size_allocated);

		//sanitizes the ints and sizes of the OMN db file, to prevent buffer overflows or read out of boundaries! 
		bool sanitize_OMN_db_file(FILE* fp, size_t full_size_of_file);
		//initializes the db status c++ map object, by reading the info insize OMN db status file (SANITIZE IT FIRST!)
		bool initialize_OMN_db_status(FILE* fp, size_t full_size_of_file);
			
		void destringify_set_of_lanNames(set<string>& s, char* buff, size_t& total_size_of_input_buffer);
};


#endif
