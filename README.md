# pk
Port knocking server and client

## Installation
To install, simply run
> sudo ./install-pk

This will create a configuration directory in `/etc/pk`, and create blank files for you. It will automatically generate a random private key as well as three random ports to be used. The script then builds the server and client applications and installs them in `/usr/local/bin`. It finally loads a `systemd` service file into `/etc/systemd/system` which you can modify and enable to run the server as a service.

## Configuration
There are six main configuration files.
### `/etc/pk/pk_key`
This file contains the private key used for cryptographically verifying that incoming knocks originate from an authorized clients. This key is generated randomly for you during installation.
### `/etc/pk/pk_ports`
This file contains the secret sequence of TCP ports which need to be knocked to authorize a client. The format is a decimal-coded port number, one per line. An example is randomly generated for you during installation.
### `/etc/pk/pkd_auth`
This file will be executed by the server when a client successfully authenticates. The IPv4 address of the authenticated client is provided as an argument in dot-decimal notation. Use this script to orchestrate modification of your firewall rules, for example.
### `/etc/pk/pkc_auth`
This file will be executed by the client when it receives notice from the server that it has successfully authenticated. You can use this, for example, to open an SSH connection to the server automatically. The IPv4 address of the server is provided as an argument in dot-decimal notation.
### `/etc/pk/pkc_prehook`
This file will be executed by the client immediately after it resolves the FQDN of the server. You may need to use this to modify your firewall rules to allow incoming packets from the server, so that the client can successfully receive the server's authentication reply.
### `/etc/pk/pkc_posthook`
This file will be executed by the client immediately before the program terminates. You may need to use this to undo any firewall modifications you made in the prehook.

## Usage
To run the server, simply specify the name of the interface to listen on:
> sudo pkd [iface]

To run the client, specify the interface to send packets on, as well as the FQDN of the machine to send them to:
> sudo pkc [iface] [fqdn]
