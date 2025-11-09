#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/wait.h>


#define LISTEN_PORT 800  // Local proxy port
#define SERVER_PORT 80    // Destination server port
#define BUFFER_SIZE 4096

int client_sock = 0;
int server_sock = 0;
int proxy_sock = 0;

void reset_sock(int *sock)
{
    if (*sock) 
    {
        close(*sock);
        *sock = 0;
    }
}

void cleanup_without_exit(void)
{
    reset_sock(&server_sock);
    reset_sock(&client_sock);
    reset_sock(&proxy_sock);
}

void cleanup(int signum)
{
    cleanup_without_exit();
    exit(0);
}

void close_connection(void)
{
    FILE *device = popen("sudo tee /sys/class/fw/conns/proxy > /dev/null", "w");
    if (!device) perror("popen proxy failed");
    
    fprintf(device, "h 0");
    pclose(device);
    
}

// Function to modify Accept-Encoding header
int remove_gzip(char *buffer) 
{
    /*
    Three situations to handle:
    no comma (only gzip)        Accept-Encoding: gzip\r\n
    comma after gzip            Accept-Encoding: gzip, deflate\r\n
    comma before gzip           Accept-Encoding: deflate, gzip\r\n
    */

    char *header_start = strstr(buffer, "Accept-Encoding: ");
    if (!header_start) return 0;  // Header not found, nothing to do

    char *line_end = strstr(header_start, "\r\n");  // Find end of line
    if (!line_end) return 0;

    char *end_of_req = buffer + strlen(buffer);

    char *gzip_pos = strstr(header_start, "gzip");
    if (!gzip_pos || gzip_pos > line_end) return 0;  // "gzip" not found or not in header
    
    // If there is a comma after " gzip", remove it
    if (gzip_pos[4] == ',') {
        memmove(gzip_pos - 1, gzip_pos + 5, end_of_req - (gzip_pos + 5));
        return 6;
    }
    // If there was a comma before " gzip", remove it
    else if (gzip_pos[-2] == ',')
    {
        memmove(gzip_pos - 2, gzip_pos + 4, end_of_req - (gzip_pos + 4));
        return 6;
    }
    else 
    {
        memmove(gzip_pos - 1, gzip_pos + 4, end_of_req - (gzip_pos + 4));
        return 5;
    }
}

//check content length
int is_illegal_response(char *buffer)       
{
    unsigned int size;
    char *ptr = strstr(buffer, "Content-Length: ");
    if (!ptr) return 0;
    char *command = strtok(ptr, "\r\n");
    if (sscanf(command, "Content-Length: %u", &size) != 1) return 0;
    return (size > 102400);
}

// Function to create a socket and connect to a destination
int connect_to_server(unsigned int server_ip, int server_port) 
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

    unsigned int ftp_server_ip, http_server_ip;
    if (fscanf(device, "%u %u", &ftp_server_ip, &http_server_ip) != 2)
    {
        perror("read server ip failed");
        fclose(device);
        return 0;
    }
    fclose(device);

    return http_server_ip;
}

// Function to handle client connection
void handle_client(void) 
{
    unsigned int server_ip = get_server_ip();
    if (!server_ip) 
    {
        perror("could not read server ip");
        cleanup(0);
    }
    
    server_sock = connect_to_server(server_ip, SERVER_PORT);
    if (server_sock < 0) 
    {
        perror("could not connect server");
        server_sock = 0;
        cleanup(0);
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read, bytes_sent;
    pid_t pid = fork();

    if (!pid)
    {
        //child process handles client->server traffic
        signal(SIGINT, cleanup);

        while (1) 
        {
            // Forward data from client to server
            bytes_read = recv(client_sock, buffer, sizeof(buffer), 0);
            if (bytes_read > 0) 
            {
                int removed_bytes = remove_gzip(buffer);
                if (removed_bytes);
                bytes_sent = send(server_sock, buffer, bytes_read - removed_bytes, 0);
                if (bytes_sent < 0) break;
            }
            // Exit loop if client closes connection
            else break;
        }
    }
    else
    {
        //parent process handles server->client traffic
        while(1)
        {
            // Forward data from server to client
            bytes_read = recv(server_sock, buffer, sizeof(buffer), 0);
            if (bytes_read > 0) 
            {
                if (is_illegal_response(buffer))
                {
                    close_connection();
                    kill(pid, SIGINT);
                    break;
                }
                bytes_sent = send(client_sock, buffer, bytes_read, 0);
                if (bytes_sent < 0) break;
            }
            // Exit loop if server closes connection
            else break;
        }
        
        int status;
        waitpid(pid, &status, 0);
    }

    cleanup(0);
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
        reset_sock(&proxy_sock);
        exit(EXIT_FAILURE);
    }

    if (listen(proxy_sock, 5) < 0) 
    {
        perror("Listen failed");
        reset_sock(&proxy_sock);
        exit(EXIT_FAILURE);
    }

    while (1) 
    {
        client_sock = accept(proxy_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) 
        {
            perror("Accept failed");
            client_sock = 0;
            continue;
        }

        pid_t pid = fork();

        if (!pid) 
        {
            // child process handles client
            signal(SIGINT, cleanup);
            reset_sock(&proxy_sock);
            handle_client();
        }
        else 
        {
            // parent process keeps listening
            reset_sock(&client_sock);
            int status;
            waitpid(pid, &status, 0);
        }
        
    }

    cleanup(0);
    return 0;
}