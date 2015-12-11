# jvision
A python script that uses junos-eznc and consequently ncclient and
NETCONF to massively retrieve operational data from a number of Juniper 
equipment. The data is extracted using a YAML file that defines the required
table views.
Results are tracked in log file.

Data supported in this version:
    --vlans flag or
    --ifces flag or
    --inventory or
    --macs (with optional --findmac flag) or

Example Usage:
jvision.py --hosts hosts_file.txt --log=DEBUG --inventory
