# jvision
A python script that uses junos-eznc and consequently ncclient and
NETCONF to massively retrieve operational data from a number of Juniper 
equipment. The data is extracted using a YAML file that defines the required
table views.
Results are tracked in log file.

Data supported in this version:
- inventory
- switching table
- vlan
- interfaces information

Example Usage:
jvision.py --hosts hosts_file.txt --log=DEBUG --inventory
