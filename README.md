# OMN


OMN is a CLI framework meant to let you portscan NAT-ed clients.

OMN uses multicast to communicate across all LANs, so you'll need to be able to setup a protocol like PIM-SM, cause all OMN nodes can be multicast sources.

OMN natively uses IP 239.192.0.66 and port 8970.

In OMN there are two types of nodes:

Master -> the master node is unique across all the network. Its name tells it all: it is the node who's deputed to command other OMN slaves; when you run it, it will search for all other nodes inside the network and then command them as you asked (scanning, result retrieval, etc...).

Slaves -> the slave nodes are present across all the network, you can put as many slave nodes as you want in your network. They will execute the commands sent by the master, and occasionally (if the result type is of a scan NMAP result) will save them (remember, since communication is done via multicast, each node will receive all data sent by other nodes).

OMN uses a GPG-based multicast mutual authentication protocol to safeguard itself from malicious entities who want to use it without authorization.

This product includes software written and developed by Code 5520 of the Naval Research Laboratory (NRL).

It uses NORM v. 1.5.9 in order to make IP multicast communication an affidable communication (like TCP).

----------------------------------------INSTALLATION-------------------------------------------------- 

To try OMN in your system just extract the src-norm-1.5.9.tgz file (https://github.com/USNavalResearchLaboratory/norm/releases/tag/v1.5.9) outside omn directory (the same directory where the build.sh is stored).

You'll need the following libraries too, from apt-get: libncurses, libgpgme, libgcrypt.

After downloading them all, launch the build.sh script file.

After it, go inside the installer folder, under "omn" folder and continue the installation of OMN by reading the README.txt file.
