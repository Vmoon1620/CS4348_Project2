/*
In this project, you will use socket connections for message passing between processes running on different machines. Additionally, you will use multithreading to send and receive messages in parallel. 

Assumptions
• There are four processes in the system, numbered from 1 to 4. Each process is run on a separate machine. You
cannot log directly into these machines. First, you need to be on the university network. 
• There are reliable socket connections (TCP) between each pair of processes.
• Each process is listening for incoming messages from other nodes.
• Each process, upon starting, takes input from the user.

Functionalities
• The inputs from the user are the command being handled at the processes. In this project, the only commands
to be implemented are as follows:
– Send message to another process: The following command should send a message to the specified
process:
send receiver id MESSAGE
(e.g.: ”send 1 Hello!” sends Hello! to process 1)

– Send message to all processes: The following command should send a message to all the other three
processes:
send 0 MESSAGE
(e.g.: ”send 0 Hello!” sends Hello! to all processes)

– Stop: sends a Stop message to all other processes, and marks own state as stopped. When a process has
received Stop messages from all other processes and its own state is stopped, the process can close all its
socket connections and exit.


For the purpose of this project, assume that the value of receiver id is in the range 1 through 4, and a process
does not send a message to itself. Also, sending a message to all the other processes is to be implemented as
three separate messages, one sent to each recipient, with the same content.

*/