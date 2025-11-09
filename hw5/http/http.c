#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/wait.h>


#define HTTP_LISTEN_PORT 800    
#define SMTP_LISTEN_PORT 250    
#define HTTP_SERVER_PORT 80    
#define SMTP_SERVER_PORT 25
#define BUFFER_SIZE 4096
#define MAX_RATIO_NOMINATOR 1
#define MAX_RATIO_DENOMINATOR 50
// MAX_RATIO = 0.02

int client_sock = 0;
int server_sock = 0;
int proxy_sock = 0;
char login_nonce[65];
int p[2];       // pipe

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

// SIGINT handler
void cleanup(int signum)
{
    cleanup_without_exit();
    if (p[0]) close(p[0]);
    if (p[1]) close(p[1]);
    exit(0);
}

// close connection in connection table
void close_connection(int is_http)
{
    FILE *device = popen("sudo tee /sys/class/fw/conns/proxy > /dev/null", "w");
    if (!device) perror("popen proxy failed");
    
    if (is_http) fprintf(device, "h 0");
    else fprintf(device, "s 0");
    pclose(device); 
}

// check login_nonce with stored values
int invalid_login_nonce(char *buffer)
{
    // p[0] is open (reading end of pipe)

    char *target = strstr(buffer, "POST /?rest_route=/reallysimplessl/v1/two_fa/skip_onboarding HTTP/1.1");
    if (!target) return 0;      // vulnerability is in skip_onboarding

    char *data = strstr(buffer, "\"login_nonce\":");
    if (!data) return 0;        // no login_nonce detected

    if (sscanf(data, "\"login_nonce\":\"%[^\"]s", login_nonce) != 1)
    {
        perror("reading login_nonce from client");
        return 0;
    }

    char actual_nonce[65];
    while (read(p[0], actual_nonce, sizeof(actual_nonce)) >= 0)
    {
        // if login_nonce is valid: accept request
        if (!strcmp(login_nonce, actual_nonce)) return 0;
    }
    return 1;       // accessing with an invalid login_nonce
}

// If login_nonce is sent by server - store it (i.e. write to pipe)
void store_login_nonce(char *buffer)
{
    // p[1] is open (writing end of pipe)
    char *data = strstr(buffer, "\"login_nonce\":");
    if (!data) return;

    if (sscanf(data, "\"login_nonce\":\"%[^\"]s", login_nonce) != 1)
    {
        perror("reading login_nonce from server");
        return;
    }
    // storing login nonce in both processes
    if (write(p[1], login_nonce, sizeof(login_nonce)) < 0) perror("writing login_nonce to pipe");
}

// Based on analysis of char frequency in both C code and textbooks
int is_special_char(char c)
{
    return ((c == '#') || (c == '(') || (c == ')') || (c == '*') || 
    (c == '+') || (c == '=') || (c == '@') || (c == '\\') || (c == '^') || 
    (c == '_') || (c == '{') || (c == '|') || (c == '}') || (c == '~'));
}

unsigned int count_special_chars(char *buffer, unsigned int len)
{
    int i;
    unsigned int count = 0;
    for (i = 0; i < len; i++)
    {
        if (is_special_char(buffer[i])) count++;
    }

    return count;
}


// Function to prevent exporting c code
int DLP(char *buffer, unsigned int len)
{
    if (!buffer || !len) return 0;
    // MAX_RATIO < (# special chars) / len         =>      suspicious behavior
    return ((len * MAX_RATIO_NOMINATOR) < (count_special_chars(buffer, len) * MAX_RATIO_DENOMINATOR));
}

// Function to modify Accept-Encoding header
int remove_gzip(char *buffer, int is_http) 
{
    // don't do anything for smtp
    if (!is_http) return 0;

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
int is_illegal_response(char *buffer, int is_http)       
{
    if (!is_http) return 0;
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

// Get server ip from kernel
unsigned int get_server_ip(int is_http)        
{
    FILE *device = fopen("/sys/class/fw/conns/proxy", "r");
    if (!device)
    {
        perror("device fopen failed");
        return 0;
    }

    unsigned int ftp_server_ip, http_server_ip, smtp_server_ip;
    if (fscanf(device, "%u %u %u", &ftp_server_ip, &http_server_ip, &smtp_server_ip) != 3)
    {
        perror("read server ip failed");
        fclose(device);
        return 0;
    }
    fclose(device);

    if (is_http) return http_server_ip;
    else return smtp_server_ip;
}

// Function to handle client connection
void handle_client(int is_http) 
{
    unsigned int server_ip = get_server_ip(is_http);
    if (!server_ip) 
    {
        perror("could not read server ip");
        cleanup(0);
    }
    
    server_sock = connect_to_server(server_ip, (is_http ? HTTP_SERVER_PORT : SMTP_SERVER_PORT));
    if (server_sock < 0) 
    {
        perror("could not connect server");
        server_sock = 0;
        cleanup(0);
    }

    // creating a pipe for login_nonce transfer
    if (pipe(p) < 0)
    {
        perror("pipe failed");
        cleanup(0);
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read, bytes_sent;
    pid_t pid = fork();
    int kill_connection = 0;        // if 0 close connection gracefully, else drop packets

    

    if (!pid)
    {
        //child process handles client->server traffic
        signal(SIGINT, cleanup);
        close(p[1]);        // closing writing end
        p[1] = 0;

        // set the reading end to not block: legal access requires the nonce to be sent before read
        int flags = fcntl(p[0], F_GETFL, 0);
        fcntl(p[0], F_SETFL, flags | O_NONBLOCK);

        int http_headers = 0;
        int smtp_headers = 0;
        while (1) 
        {
            // Forward data from client to server
            bytes_read = recv(client_sock, buffer, sizeof(buffer), 0);
            if (bytes_read > 0) 
            {

                int removed_bytes = remove_gzip(buffer, is_http);
                
                // IPS
                if (invalid_login_nonce(buffer))
                {
                    printf("IPS detected exploit attempt\n");
                    kill_connection = 1;
                    break;
                }

                // DLP
                // for http - skip headers to get actual data
                if (is_http && !http_headers) 
                {
                    // file transfers will enter twice, while plain text will enter once
                    if (!strstr(buffer, "Content-Type: multipart")) http_headers = 1; 
                }
                // for smtp - skip the irrelevant headers
                else if (!is_http && !smtp_headers)
                {
                    // if we reached data, change smtp_headers
                    if (!strncmp(buffer, "DATA", 4)) smtp_headers = 1;
                }
                // reached actual data
                else if (DLP(buffer, bytes_read - removed_bytes))
                {
                    printf("DLP: C code detected\n");
                    kill_connection = 1;
                    break;
                }

                bytes_sent = send(server_sock, buffer, bytes_read - removed_bytes, 0);
                if (bytes_sent < 0) break;
            }
            // Exit loop if client closes connection
            else break;
        }
        
        // Tell parent process (handling server->client) to close connection
        cleanup_without_exit();
        kill(getppid(), SIGINT);
        close(p[0]);
        p[0] = 0;
        if (kill_connection) close_connection(is_http);
    }
    else
    {
        //parent process handles server->client traffic
        close(p[0]);        // closing reading end
        p[0] = 0;
        while(1)
        {
            // Forward data from server to client
            bytes_read = recv(server_sock, buffer, sizeof(buffer), 0);
            if (bytes_read > 0) 
            {
                store_login_nonce(buffer);

                if (is_illegal_response(buffer, is_http)) 
                {
                    kill_connection = 1;
                    break;
                }

                bytes_sent = send(client_sock, buffer, bytes_read, 0);
                if (bytes_sent < 0) break;
            }
            // Exit loop if server closes connection
            else break;
        }
        // Tell child process (handling client->server) to close connection
        cleanup_without_exit();
        kill(pid, SIGINT);
        close(p[1]);
        p[1] = 0;
        int status;
        waitpid(pid, &status, 0);
        if (kill_connection) close_connection(is_http);
    }

    exit(0);
}


int main() 
{
    struct sockaddr_in proxy_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    unsigned short port;
    int is_http;
    login_nonce[64] = '\0';     // login_nonce is a 32 byte string
    p[0] = 0;
    p[1] = 0;
    
    if (fork()) 
    {
        // Parent process for http
        signal(SIGINT, cleanup);
        is_http = 1;
        port = HTTP_LISTEN_PORT;
    }
    else 
    {
        // Child process for smtp
        signal(SIGINT, cleanup);
        is_http = 0;
        port = SMTP_LISTEN_PORT;
    }
    
    proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_sock < 0) 
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(proxy_sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR) failed");
        reset_sock(&proxy_sock);
        exit(EXIT_FAILURE);
    }
    

    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = INADDR_ANY;
    proxy_addr.sin_port = htons(port);

    if (bind(proxy_sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) 
    {
        fprintf(stderr, "Bind failed for %s proxy", is_http ? "HTTP" : "SMTP");
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
            handle_client(is_http);
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