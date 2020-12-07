# wgnet - WireGuard network tool

The WireGuard wg-quick and wg tools, by design, only control the bring up and teardown of the actual interface, and have limited support for managing a network.  Even the documentation for wg-quick says "users with more advanced needs are highly encouraged to use a more specific tool".

wgnet is designed to manage a WireGuard network, including more advanced routing and firewall tools.

## Usage
```
Usage: wgnet <config> <command>
   config           Configuration to operate on 
   command          Action to take on the config
        status (default)  Show the status of the config
        showconf          Show the saved config settings
        new               Create a new config
        up                Bring up the named config
        down              Tear down the named config
        restart           Restart the named config, (reloads all parameters from config file)

   --dryrun, -D     Dry run, don't actually do changes
   --path, -P       Set the path of the config files (Default: /etc/wgnet/)
   -L               List config files and directory, and exit
   -F               Force operations (Be careful)
   -v               Enable verbose output
   --version, -V    Print version info and exit
   -h?              Program help (This output)
```

## Configuration files

Example configuration file (found in configs/server1.conf for testing)
```
# Test config file for wg0 network
interface = wg0

# By default, routing a subnetworks if the linux system is has
# routing enabled, turn off subnet routing here. Add additional subnets
# to allow here
routing {
    RouteSubnet = true
    Networks = {"192.168.100.0/24","12.34.56.78/16","1.2.3.4/8"}
}

# By default, individual host forwarding is denied. Add in
# exceptions here
firewall_host {
    Host = "192.168.0.1"
    AllowedPorts = {80}
}

firewall_host {
    Host = "192.168.1.2"
    AllowedPorts = {80,443}
}

firewall_host {
    Host = "192.168.1.4"
    AllowedPorts = {22,1234,5678}
}

```


## Examples

|  | Command |
|-----------------|:-------------|
| Show status of config files and running WireGuard interfaces | sudo wgnet |
| Show status of config 'wg-client1net' |  sudo wgnet wg-client1net status |
| Show the config file of config; 'wg-client1net' |  sudo wgnet wg-client1net showconf |
| Create a new config 'newclient' with some initial parameters |  sudo wgnet newnet new |

## Libraries

wgnet requires libconfuse.  Packages should be available for all systems:

sudo dnf install libconfuse libconfuse-devl
sudo apt install libconfuse-common libconfuse-dev

## Make & Install

wgnet uses native GCC on the system

```
make
make install
```

## License

wgnet is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License (GPL) version 2.
