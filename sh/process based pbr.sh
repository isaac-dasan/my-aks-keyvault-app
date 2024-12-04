# To build a container image where some processes run with UID 1000 and others with UID 1001,
#  and ensure these processes connect to different routes based on IP rules, you can follow these steps:

# Create a Dockerfile: This Dockerfile will set up the environment, create users, and configure the processes.
# Use a base image
FROM ubuntu:latest

# Install necessary tools
RUN apt-get update && apt-get install -y iproute2 iptables cgroup-tools

# Create users with specific UIDs
RUN useradd -u 1000 user1000 && useradd -u 1001 user1001

# Create directories for processes
RUN mkdir /home/user1000_process && mkdir /home/user1001_process

# Set up scripts to run processes
COPY run_user1000.sh /home/user1000_process/
COPY run_user1001.sh /home/user1001_process/

# Make scripts executable
RUN chmod +x /home/user1000_process/run_user1000.sh
RUN chmod +x /home/user1001_process/run_user1001.sh

# Switch to user1000 and run the first process
USER user1000
CMD ["/home/user1000_process/run_user1000.sh"]

# Switch to user1001 and run the second process
USER user1001
CMD ["/home/user1001_process/run_user1001.sh"]
Create the Process Scripts: Create run_user1000.sh and run_user1001.sh scripts to run the processes.
run_user1000.sh:

#!/bin/bash
# Example process for user1000
echo "Running process as user1000"
# Your process command here
sleep infinity
run_user1001.sh:

#!/bin/bash
# Example process for user1001
echo "Running process as user1001"
# Your process command here
sleep infinity
Build the Docker Image: Build the Docker image using the Dockerfile.
docker build -t myimage:latest .
Run the Docker Container: Run the container and ensure the processes are started.
docker run -d --name mycontainer myimage:latest
Configure cgroups and IP Rules: After starting the container, configure cgroups and IP rules on the host to route traffic based on the process UIDs.
# Create cgroups
sudo cgcreate -g net_cls:/group1000
sudo cgcreate -g net_cls:/group1001

# Assign class IDs
echo 0x100001 > /sys/fs/cgroup/net_cls/group1000/net_cls.classid
echo 0x100002 > /sys/fs/cgroup/net_cls/group1001/net_cls.classid

# Find PIDs of the processes
pid1000=$(docker exec mycontainer pgrep -u 1000)
pid1001=$(docker exec mycontainer pgrep -u 1001)

# Assign PIDs to cgroups
sudo cgclassify -g net_cls:group1000 $pid1000
sudo cgclassify -g net_cls:group1001 $pid1001

# Configure iptables to mark packets
sudo iptables -t mangle -A OUTPUT -m cgroup --cgroup 0x100001 -j MARK --set-mark 100
sudo iptables -t mangle -A OUTPUT -m cgroup --cgroup 0x100002 -j MARK --set-mark 101

# Add routing rules
sudo ip rule add fwmark 100 table 100
sudo ip rule add fwmark 101 table 101

# Configure routing tables
sudo ip route add default via <gateway_for_100> dev <interface> table 100
sudo ip route add default via <gateway_for_101> dev <interface> table 101

# This setup ensures that processes running with UID 1000 and UID 1001 are routed according to the specified IP rules. 
#Adjust the gateways and interfaces as per your network configuration.