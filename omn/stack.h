#include "OMN_common.h"

typedef struct {
    NormNodeId his_NORMID;
    int challengeReceivedFromHim;
    int token_for_him;
} Data_slave;


//remember to free the returned pointer
char* stringify_vector_of_Data_slave(std::vector<Data_slave>& v, size_t& string_length);
//ALWAYS SANITIZE SV, CHECK BOUDNARIES AND SIZE (STORED AT THE START OF SV): sv length in byte MUST BE "sizeof(long) + sizeof(Data_slave)*size".
void destringify_vector_of_Data_slave(std::vector<Data_slave>& destination, char* sv);

bool find_data_slave(std::vector<Data_slave>& v_nodes, NormNodeId e, long& index);

