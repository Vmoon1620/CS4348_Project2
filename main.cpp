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


#include <iostream>
#include <thread>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <mutex>

const int NUM_PROCESSES = 4; //We will be having 4 processes in total
const int BASE_PORT = 8080; // Use different ports for different processes

enum class ProcessState
{
    Running,
    Stopped
};

std::vector<ProcessState> process_states(NUM_PROCESSES, ProcessState::Running);
std::mutex process_state_mutex;

// Parses user input and send messages to the other processes
void parseAndSendMessage(int processID, const std::string &input, const std::vector<int> &client_sockets)
{
    if (input.substr(0, 4) != "send" && input != "Stop")
    {
        // if send or Stop is not found throw error
        std::cout << "Invalid command. Usage: send receiver_id message or Stop\n\n";
        return;
    }

    if (input == "Stop")
    {
        // Processes will be stopped
        std::lock_guard<std::mutex> lock(process_state_mutex);
        process_states[processID - 1] = ProcessState::Stopped;

        // Send the Stop message to all other processes
        for (int i = 1; i <= NUM_PROCESSES; ++i)
        {
            if (i != processID)
            {
                std::cout << "Stop message sent to Process " << i << "\n";
            
            }
        }
    }
    else
    {
        // Parse the input for send command
        std::size_t position = input.find(' ');

        //if no spaces throw error
        if (position == std::string::npos)
        {
            std::cout << "Invalid command. Usage: send receiver_id message\n";
            return;
        }

        //Grabs recieverID if valid
        int receiverID;
        try
        {
            receiverID = std::stoi(input.substr(5, position - 5));
        }
        catch (...)
        {
            std::cout << "Invalid receiver ID. Usage: send receiver_id message\n";
            return;
        }

        //this caputes the message that is going to be sent
        std::string message = input.substr(position + 1);

        if (receiverID == 0)
        {
            // Send the message to all other processes
            for (int i = 1; i <= NUM_PROCESSES; ++i)
            {
                if (i != processID)
                {
                    //attempts to send message to all processes
                    if (send(client_sockets[i - 1], message.c_str(), message.size(), 0) == -1)
                    {
                        std::cerr << "Failed to send message to Process " << i << "\n";
                    }
                    else
                    {
                        std::cout << "Message sent to Process " << i << ": " << message << "\n";
                    }
                }
            }
        }
        //Processes 1-4
        else if (receiverID >= 1 && receiverID <= NUM_PROCESSES)
        {
            // Send the message to the specified receiving process
            if (send(client_sockets[receiverID - 1], message.c_str(), message.size(), 0) == -1)
            {
                std::cerr << "Failed to send message to Process " << receiverID << "\n";
            }
            else
            {
                std::cout << "Message sent to Process " << receiverID << ": " << message << "\n";
            }
        }
        else
        {
            std::cout << "Receiver ID must be between 1 and " << NUM_PROCESSES << ", or 0 to send to all processes.\n";
        }
    }
}

// Server deals with incoming messages 
void serverThread(int processID, const std::vector<int> &client_sockets)
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    char buffer[1024] = {0};

    // Create a socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;

    //starting BASE_PORT = 8080;
    server_addr.sin_port = htons(BASE_PORT + processID);

    // this binds the process Id to thier port number
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Process " << processID << ": Bind failed\n";
        return;
    }

    // Listen
    listen(server_socket, 4);

    std::cout << "Process " << processID << " listening on port " << (BASE_PORT + processID) << "\n";

    // Accept incoming connections and stores client adr information
    socklen_t client_addr_size = sizeof(client_addr);
    client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_size);
   

    std::cout << "Process " << processID << ": Connection accepted from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << "\n";

    while (true)
    {
        // Receive a message from other processes
        memset(buffer, 0, sizeof(buffer));
        int valread = read(client_socket, buffer, sizeof(buffer));
        if (valread <= 0)
        {
            std::cerr << "Process " << processID << ": Connection closed by the remote process\n";
            //Process will be stopped
            //Locks mutex
            std::lock_guard<std::mutex> lock(process_state_mutex);
            process_states[processID - 1] = ProcessState::Stopped;
            break;
        }

        std::string received_message(buffer);

        if (received_message == "Stop")
        {
            // Received Stop message from another process
            std::cout << "Process " << processID << " received Stop message.\n";
            // Mark the sender process's state as stopped
            std::lock_guard<std::mutex> lock(process_state_mutex);
            process_states[processID - 1] = ProcessState::Stopped;
        }
        else
        {
            std::cout << "Process " << processID << " received: " << received_message << "\n";
        }
    }

    close(client_socket);
    close(server_socket);
}

// Function to handle user I/O and send messages 
void clientThread(int processID, const std::vector<int> &client_sockets)
{
    int client_socket;
    struct sockaddr_in server_addr;
    char buffer[1024] = {0};

    // Create a socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
 
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(BASE_PORT + processID);

    // Convert IP address from string to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0)
    {
        std::cerr << "Process " << processID << ": not valid IP address\n";
        return;
    }

    // Connecting to  server
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Process " << processID << ": Connection failed\n";
        return;
    }

    std::cout << "Process " << processID << " connected to server\n";

    

    while (true)
    {
        // Take input from the user
        std::cout << "Process " << processID << " Enter command: \n";
        std::string input;
        std::getline(std::cin, input);

        // Send the message to the  receiver process or Stop 
        parseAndSendMessage(processID, input, client_sockets);

        // Check if the process should stop
        bool all_stopped = true;
        {
            std::lock_guard<std::mutex> lock(process_state_mutex);
            for (int i = 0; i < NUM_PROCESSES; ++i)
            {
                if (i != processID && process_states[i] == ProcessState::Running)
                {
                    all_stopped = false;
                    break;
                }
            }
        }

        if (process_states[processID - 1] == ProcessState::Stopped && all_stopped)
        {
            std::cout << "Process " << processID << " has received Stop messages from all other processes and is marked as stopped.\n";
            break;
        }
    }

    close(client_socket);
}

int main()
{
    std::vector<std::thread> threads;
    std::vector<int> client_sockets(NUM_PROCESSES);

    // Starts server for each process
    for (int i = 1; i <= NUM_PROCESSES; ++i)
    {
        threads.push_back(std::thread(serverThread, i, std::ref(client_sockets)));
    }

    // Sleep for a short time to ensure all server threads are ready to listen
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Start the client threads for each process
    for (int i = 1; i <= NUM_PROCESSES; ++i)
    {
        client_sockets[i - 1] = socket(AF_INET, SOCK_STREAM, 0);
        if (client_sockets[i - 1] == -1)
        {
            std::cerr << "Process " << i << ": Failed to create client socket\n";
            continue;
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(BASE_PORT + i);
        if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0)
        {
            std::cerr << "Process " << i << ": Not valid IP Address\n";
            close(client_sockets[i - 1]);
            continue;
        }

        if (connect(client_sockets[i - 1], (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            std::cerr << "Process " << i << ": Connection failed\n";
            close(client_sockets[i - 1]);
            continue;
        }

        std::cout << "Process " << i << " connected to server\n";
        threads.push_back(std::thread(clientThread, i, std::ref(client_sockets)));
    }

    // Wait for all processes to stop before closing the sockets and exiting
    for (int i = 1; i <= NUM_PROCESSES; ++i)
    {
        threads[i - 1].join();
    }

    // Close all client sockets
    for (int i = 1; i <= NUM_PROCESSES; ++i)
    {
        close(client_sockets[i - 1]);
    }

    return 0;
}







