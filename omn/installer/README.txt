This folder contains the program to generate the slave/commander GPG keypairs, and the OMN_cfg.txt config file (to save OMN keypair's fingerprints).

Mind that slaves secret keys will not be password protected, cause they are meant for a server enviroment.

First program you should run is the one meant to generate OMN master's and slave group's keypair: the  "OMN_gen_and_export_keypairs.out" executable.
After running the program, the program will create a .cfg file inside the "~/.OMN/" folder and you will be able to run the "master.out" file.

It will give you a .txt file too, containing the master's pubkey and slave group's keypair:
When you will install a new OMN slave, you will need to take a USB pendrive and copy it in the slave's installer folder; after doing so, you can run 
the "OMN_import_for_slave.out" executable to import the GPG keys and create the relative OMN config file for the slave. 
After running the executable, you will be able to run the "slave.out" file.

------------------------------------------
---IMPORTANT----IMPORTANT----IMPORTANT----
------------------------------------------
   YOU DON'T NEED TO IMPORT KEYS ON THE
    SAME HOST WHERE YOU CREATED THEM!
THEY ARE ALREADY SAVED IN THE GPG ENGINE!
------------------------------------------
---IMPORTANT----IMPORTANT----IMPORTANT----
------------------------------------------
