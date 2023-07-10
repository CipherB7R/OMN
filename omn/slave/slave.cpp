
#include "OMN_slaves.h"  // for Common OMN definitions


#ifdef WIN32
const char DIR_DELIMITER = '\\';
#else
const char DIR_DELIMITER = '/';
#endif // if/else WIN32/UNIX

pthread_mutex_t gpgme_crypto_ctx_mutex;
pthread_mutex_t mutex_execute_command;

int main(int argc, char* argv[])
{

    //0) Initialize the GPGME engine.
    char lan_name[LAN_NAME_LENGTH] = "";
    init_gcrypt();
    init_gpgme();
    
    SlaveCryptoCtx slave_crypto_ops_ctx;
    slave_crypto_ops_ctx.init_crypto_context();

    if(slave_crypto_ops_ctx.my_lan_name.size() < LAN_NAME_LENGTH) {
	memcpy(lan_name, slave_crypto_ops_ctx.my_lan_name.c_str(), sizeof(char) * slave_crypto_ops_ctx.my_lan_name.size());
    } else {
	
	    fprintf(stderr, "Wrong size of lan name. Exiting.\n");
	    exit(-1);
	
    }

    while(true) {

	    bool set_tx_rate = false;
	    double rate = 0;
	    bool enable_message_trace = false;
	    Data_lockedon_master master_omn; //undefined till we get him!
	    Command cmd;

	    pthread_mutex_init(&mutex_execute_command, NULL);
	    pthread_mutex_init(&gpgme_crypto_ctx_mutex, NULL);



	    // 1) Create a NORM API "NormInstance"
	    NormInstanceHandle instance = NormCreateInstance();
	    
	    // 2) Create a NormSession using a generated local_id
	    NormSessionHandle session = OMNCreateSession(instance, slave_crypto_ops_ctx.local_NORMid);


	    
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
	    // 	    1MB buffer space 
	    NormStartReceiver(session, 1024*1024);

	    //TODO: enclose in {} A NODESomn VECTOR in order to do the distributed database stuff.
	    std::vector<Data_slave> other_slaves;

	    // 5) SUBSCRIBE PHASE
	    
	    cmd = OMN_subscribe(instance, session, slave_crypto_ops_ctx, &master_omn, other_slaves);

	    // 6) EXECUTE COMMAND PHASE
	    // 		TOGETHER WITH...
	    // 7) SEND RESULTS PHASE

	    //Ok, we managed to receive a command. Now there are two cases:
	    //	A) The response can be quickly calculated, like in the case OMN is just asking for our LAN name.
	    //	B) The response can take quite some time to be calculated, like in the case OMN is asking for a NMAP or NESSUS scan.
	    //
	    //	A is typical for information requests. B is typical for commands that need an excve fork/waitpid to be executed.
	    //	
	    //	There is one problem: in order to receive the results from other authenticated slaves (for the distributed database part),
	    //	we need to be "active" in the main thread; This means we can't just create a C++ procedural/imperative function 
	    //	like "Response execute_command(Command cmd)" and then a call to "void Send_results(Response rsp)" because in case B 
	    //	we can't have the response ready right away, and waiting for it means we will lose some NORM messages in the mean time!
	    //
	    //	We have to do something complicated to overcome this.
	    //
	    //	We will create a thread: this way we will have two threads:
	    //	MAIN: 
	    //		will continue the execution like nothing happened. 
	    //	      	Will be the only one to have access to NORM thread.
	    //	      	Will be the only one to have access to GPGME engine.
	    //	      	Will wait for the second one to return a response.
	    //
	    //	Secondary: 
	    //		will execute the "Send_results" function, that is, the OMN command with it.
	    //		Will execute the fork for the eventual NMAP execution.
	    //		Will RETURN a pointer to an respose structure in the heap.
	    //	
	    //	They will share three values, all contained in a handful structure (execute_command_parms) in the MAIN thread's stack:
	    //		bool response_avaliable: MAIN will unlock mutex if this variable is still false. 
	    //					 SECONDARY will lock mutex when possible, and will unlock it only if it changes this variable to true.
	    //		Response rsp:  Response structure. If response_avaliable is true, it will be valid and full of response.
	    //			       otherwise, it means the SECONDARY is still executing the command and will later fill it up.
	    //		Command cmd:   Command structure. Contains the command to be executed.
	    //
	    //
	    //	We will use pthread_mutex_trylock in MAIN and pthread_mutex_lock in SECONDARY.
	    //	Let's go!
		
	    Execute_command_parms thread_exeCmd_params;
	    thread_exeCmd_params.cmd = cmd;
	    thread_exeCmd_params.slave_crypto_ctx = &slave_crypto_ops_ctx;
	    thread_exeCmd_params.lan_name = lan_name;
	    thread_exeCmd_params.response_avaliable = false;

	    //thread_exeCmd_params.rsp is INVALID.
	    
	    pthread_t thread_exeCmd_id;
	    if(pthread_create(&thread_exeCmd_id, NULL, &execute_command, &thread_exeCmd_params) != 0) {
		fprintf(stderr, "ERROR! Couldn't create command execution thread. ABORTING!\n");
		exit(-1);
	    }


	    //TODO: waitpid non blocking for SECONDARY, tryjoin thread non blocking for MAIN.
	    //TODO: remember to free the opt_data of the command AFTER SECONDARY returns.
	    std::vector<EpkMaster_RESP> v_RESPs;
	    OMN_sendResult(instance, session, slave_crypto_ops_ctx, &master_omn, &thread_exeCmd_params, &thread_exeCmd_id, cmd, other_slaves, v_RESPs);


	    //8) PROCESS THE RESPONSES!
	    process_RESPs(v_RESPs, cmd);	

	    if(cmd.len > 0) {
		free(cmd.opt_data);
	    }

	    other_slaves.clear();

	    //No need for receiver role anymore...
	    printf("Stopping receiver...\n");
	    NormStopReceiver(session);
	    //let's send the results!
	    

	    // 9) END! 
	    NormStopSender(session);

	    NormDestroySession(session);
	    NormDestroyInstance(instance);
	    
	    pthread_mutex_destroy(&mutex_execute_command);
	    pthread_mutex_destroy(&gpgme_crypto_ctx_mutex);

    }

    slave_crypto_ops_ctx.destroy_crypto_context();

    fprintf(stdout, "OMN process: Done.\n");
    return 0;
}  // end main()

