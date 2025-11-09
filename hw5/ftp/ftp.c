#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/wait.h>

#define LISTEN_PORT 210  // Local proxy port towards client
#define SERVER_PORT 21    // Destination server port
#define BUFFER_SIZE 4096

int client_sock = 0;
int server_sock = 0;
int proxy_sock = 0;


void cleanup(int signum)
{
    if (client_sock) close(client_sock);
    if (server_sock) close(server_sock);
    if (proxy_sock) close(proxy_sock);
    exit(0);
}

unsigned short extract_port(char *buffer)
{
    char *ptr = strstr(buffer, "PORT ");
    if (ptr) 
    {
        char *command = strtok(ptr, "\r\n");
        unsigned int ip1, ip2, ip3, ip4;
        unsigned short port1, port2;
        if (sscanf(command, "PORT %u,%u,%u,%u,%hu,%hu", &ip1, &ip2, &ip3, &ip4, &port1, &port2) != 6) return 0;
        return ((256 * port1) + port2);
    }
    return 0;
}

void handle_port_cmd(char *buffer)
{
    unsigned short port = extract_port(buffer);
    if (port)
    {
        FILE *device = popen("sudo tee /sys/class/fw/conns/proxy > /dev/null", "w");
        if (!device) perror("popen proxy failed");
        
        fprintf(device, "f %hu", htons(port));
        pclose(device);
    }
}

// Function to create a socket and connect to a destination
int connect_to_server(uint32_t server_ip, int server_port) 
{
    int sock;
    struct sockaddr_in server_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        perror("Socket creation failed");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = server_ip;

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) 
    {
        perror("Connection to server failed");
        close(sock);
        return -1;
    }

    return sock;
}

//get server ip from kernel
unsigned int get_server_ip(void)        
{
    FILE *device = fopen("/sys/class/fw/conns/proxy", "r");
    if (!device)
    {
        perror("device fopen failed");
        return 0;
    }

    uint32_t ftp_server_ip, http_server_ip, smtp_server_ip;
    if (fscanf(device, "%u %u %u", &ftp_server_ip, &http_server_ip, &smtp_server_ip) != 3)
    {
        perror("read server ip failed");
        fclose(device);
        return 0;
    }
    fclose(device);

    return ftp_server_ip;
}

// Function to handle client connection
int handle_client(void) 
{
    uint32_t server_ip = get_server_ip();
    if (!server_ip) 
    {
        perror("could not read server ip");
        return 1;
    }
    
    server_sock = connect_to_server(server_ip, SERVER_PORT);
    if (server_sock < 0) 
    {
        perror("could not connect server");
        return 1;
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read, bytes_sent;

    if (fork())
    {
        //parent process handles client->server traffic
        while (1) 
        {
            // Forward data from client to server
            bytes_read = recv(client_sock, buffer, sizeof(buffer), 0);
            if (bytes_read > 0) 
            {
                handle_port_cmd(buffer);
                bytes_sent = send(server_sock, buffer, bytes_read, 0);
                if (bytes_sent < 0) break;
            }
            // Exit loop if client closes connection
            else break;
        }
        wait(NULL);
    }
    else
    {
        //child process handles server->client traffic
        signal(SIGINT, cleanup);
        while(1)
        {
            // Forward data from server to client
            bytes_read = recv(server_sock, buffer, sizeof(buffer), 0);
            if (bytes_read > 0) 
            {
                bytes_sent = send(client_sock, buffer, bytes_read, 0);
                if (bytes_sent < 0) break;
            }
            // Exit loop if server closes connection
            else break;
        }
        
    }
    cleanup(0);
    exit(0);
}

int main() 
{
    struct sockaddr_in proxy_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    signal(SIGINT, cleanup);

    // Create listening socket
    proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_sock < 0) 
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = INADDR_ANY;
    proxy_addr.sin_port = htons(LISTEN_PORT);

    if (bind(proxy_sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) 
    {
        perror("Bind failed");
        close(proxy_sock);
        exit(EXIT_FAILURE);
    }

    if (listen(proxy_sock, 5) < 0) 
    {
        perror("Listen failed");
        close(proxy_sock);
        exit(EXIT_FAILURE);
    }

    //printf("Proxy listening on port %d...\n", LISTEN_PORT);

    while (1) 
    {
        client_sock = accept(proxy_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) 
        {
            perror("Accept failed");
            continue;
        }

        //printf("New connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    
        if (!fork()) 
        {
            // child process handles client
            signal(SIGINT, cleanup);
            close(proxy_sock);
            proxy_sock = 0;
            if (handle_client()) break;
        }
        else 
        {
            // parent process keeps on listening
            wait(NULL);
        }
    }

    cleanup(0);
    return 0;
}