
#include "stack.h"

bool find_data_slave(std::vector<Data_slave>& v_nodes, NormNodeId e, long& index) {
	
	for(long i=0; i < v_nodes.size(); i++) {

		if(v_nodes[i].his_NORMID == e) {
			index = i;
			return true;
		}
	}

	return false;

}

//remember to free the returned pointer
char* stringify_vector_of_Data_slave(std::vector<Data_slave>& v, size_t& string_length) {
	
	//allocate space for size (a long) and all elements (sizeof(Data_slave)).
	char* tmp = NULL;
	
	string_length = sizeof(long) + (sizeof(Data_slave)*v.size());
	
	tmp = (char*) malloc(string_length);
	if(tmp == NULL) {
		fprintf(stderr, "Failed to allocate space to stringify vector.\n");
		exit(-1);
	}

	//copy the vector size before all the elements.
	long vec_size = v.size();
	memcpy(tmp, &(vec_size), sizeof(long));

	//copy the real elements, starting from offset.
	char* offset = tmp + sizeof(long);
	
	for(long i = 0; i<v.size(); i++) {
		Data_slave to_be_copied = v[i];
		memcpy(offset + (i*sizeof(Data_slave)), &to_be_copied, sizeof(Data_slave));
	}

	
	return tmp;

}

//ALWAYS SANITIZE SV, CHECK BOUDNARIES AND SIZE (STORED AT THE START OF SV): sv length in byte MUST BE "sizeof(long) + sizeof(Data_slave)*size".
void destringify_vector_of_Data_slave(std::vector<Data_slave>& destination, char* sv) {
	
	long vec_size = -1;
	memcpy(&vec_size, sv, sizeof(long));

	if(vec_size < 0) {
		fprintf(stderr, "Failed to destringify vector: invalid size.\n");
		exit(-1);
	}

	char* offset = sv + sizeof(long);
	
	for(long i=0; i < vec_size; i++) {
		Data_slave tmp;
		memcpy(&tmp, offset + (i*sizeof(Data_slave)), sizeof(Data_slave));
		destination.push_back(tmp);
	}


}







