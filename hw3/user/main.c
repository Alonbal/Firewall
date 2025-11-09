
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#define error_occured(err_msg) {perror(err_msg); exit(1);}
#define error_fclose_file(file, err_msg) {fclose(file); error_occured(err_msg)}
#define error_pclose_file(file, err_msg) {pclose(file); error_occured(err_msg)}

int parse_direction(char *dir)
{
    if (!strcmp("in", dir)) return 1;
    if (!strcmp("out", dir)) return 2;
    if (!strcmp("any", dir)) return 3;
    return -1;
}

int parse_ip_addr(char *ip) 
{
    if (!strcmp(ip, "any")) return 0;
    int res, a, b, c, d, mask;
    if (sscanf(ip, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &mask) != 5) return -1;
    res = (a << 24) | (b << 16) | (c << 8) | d;
    return res;

}

int parse_mask(char *ip) 
{
    if (!strcmp(ip, "any")) return 0;
    char addr[21];
    int mask;
    if (sscanf(ip, "%[^/]/%d", addr, &mask) != 2) return -1;
    if (mask > 32) return -1;
    return mask;
}

int parse_port(char *port)
{
    int res;
    if (!strcmp(port, ">1023")) return 1023;
    else if (!strcmp(port, "any")) return 0;
    else if (sscanf(port, "%d", &res) != 1) return -1;
    return res;
}

int parse_protocol(char *protocol)
{
    if (!strcmp(protocol, "ICMP")) return 1;
    if (!strcmp(protocol, "TCP")) return 6;
    if (!strcmp(protocol, "UDP")) return 17;
    if (!strcmp(protocol, "any")) return 143;
    return -1;
}

int parse_ack(char *ack)
{    
    if (!strcmp(ack, "no")) return 1;
    if (!strcmp(ack, "yes")) return 2;
    if (!strcmp(ack, "any")) return 3;
    return -1;
}

int parse_action(char *action)
{
    if (!strcmp(action, "drop")) return 0;
    if (!strcmp(action, "accept")) return 1;
    return -1;
}

void print_direction(int direction)
{
    if (direction == 1) printf("in ");
    else if (direction == 2) printf("out ");
    else printf("any ");
}

void print_ip(unsigned int addr)
{
    addr = ntohl(addr);
    printf("%u.%u.%u.%u", (addr >> 24) & 0xff, (addr >> 16) & 0xff, 
                          (addr >> 8) & 0xff, addr & 0xff);
}

void print_ip_with_mask(unsigned int addr, unsigned int mask)
{
    if (mask == 0) printf("any ");
    else
    {
        print_ip(addr);
        printf("/%u ", mask);
    }
}

void print_protocol(unsigned int protocol)
{
    switch (protocol)
    {
    case 1:
        printf("ICMP ");
        break;

    case 6:
        printf("TCP ");
        break;
        
    case 17:
        printf("UDP ");
        break;
        
    case 143:
        printf("any ");
        break;
    
    default:
        printf("other ");       //should not happen
        break;
    }
}

void print_port(unsigned short port)
{
    //printf("\n%d %d\n", port, ntohs(port));
    switch(ntohs(port))
    {
        case 0:
            printf("any ");
            break;
        
        case 1023:
            printf(">1023 ");
            break;
        
        default:
            printf("%d ", ntohs(port));
            break;
    }
}

void print_ack(unsigned int ack)
{
    switch (ack)
    {
    case 1:
        printf("no ");
        break;
    
    case 2:
        printf("yes ");
        break;

    default:
        printf("any ");
        break;
    }
}

void print_action(unsigned int action)
{
    if (action == 0) printf("drop");
    else printf("accept");
}

void print_reason(int reason)
{
    switch (reason)
    {
    case -1:
        printf("REASON_FW_INACTIVE\t\t");
        break;
    
    case -2:
        printf("REASON_NO_MATCHING_RULE\t\t");
        break;
    
    case -4:
        printf("REASON_XMAS_PACKET\t\t");
        break;
    
    case -6:
        printf("REASON_ILLEGAL_VALUE\t\t");
        break;
    
    default:
        printf("%d\t\t\t\t", reason);       //rule number
        break;
    }
}

void print_to_device(char *device_path, char *str)
{
    int p[2];
    if (pipe(p) == -1) error_occured("pipe failed")
        
    pid_t childpid = fork();
    if (childpid == -1) error_occured("fork failed")
    char *command;
    

    if (childpid) 
    {   //parent process executes echo
        close(p[0]);
        dup2(p[1], 1);      //stdout writing to pipe
        command = "echo";
        char *arglist[] = {"echo", str, NULL};
        
        if (execvp(command, arglist) == -1) error_occured("echo failed")
    }
        
    else 
    {   //child process executes sudo tee    
        close(p[1]);
        dup2(p[0], 0);      //stdin reading from pipe
        command = "sudo";
        char *arglist[] = {"sudo", "tee", device_path, NULL};

        int devnull = open("/dev/null", O_WRONLY);    //this file is for garbage
        if (devnull == -1) error_occured("Error opening /dev/null")
        if (dup2(devnull, STDOUT_FILENO) == -1) error_occured("dup2 failed")   //redirecting stdout to /dev/null

        if(execvp(command, arglist) == -1) error_occured("Sudo tee failed")
    }
}




int main(int argc, char *argv[]) 
{
    char *path;
    char *line = NULL;
    char parsed_line[81];      //should be enough for a line
    char res[81 * 50] = "";    //should be enough for all lines
    char *member;
    int iter = 0;
    int val;
    FILE *file;
    FILE *device;
    size_t len;
        
    if (argc > 3 || argc == 1) error_occured("wrong amount of inputs")

    if (argc == 3) 
    {
        if (strcmp(argv[1], "load_rules")) error_occured("wrong input")
        //load rules from argv[2]
        path = "/sys/class/fw/rules/rules";
        char *from_path = argv[2];

        file = fopen(from_path, "r");
        
        if (!file) error_occured("fopen rules failed")
        
        while (getline(&line, &len, file) != -1)
        {
            if (iter == 50) 
            {
                fclose(file);
                error_occured("too many rules")
            }
            iter++;

            char rule_name[21];     //max size of 20
            int direction;
            char direction_str[4];  //max size of 3
            int	src_ip;
            unsigned int parsed_src_ip;
            char src_ip_str[21];    //max size of 20
            int src_prefix_size;	
            int	dst_ip;
            unsigned int parsed_dst_ip;
            char dst_ip_str[21]; 	//max size of 20
            int dst_prefix_size; 	
            int src_port;
            unsigned short parsed_src_port; 			  
            char src_port_str[11];  //max size of 10
            int dst_port;
            unsigned short parsed_dst_port; 		
            char dst_port_str[11];	//max size of 10
            int	protocol; 		
            char protocol_str[6];	//max size of 5 (should be 3, but just in case...)
            int	ack;
            char ack_str[5];	    //max size of 3
            int	action;
            char action_str[7];     //max size of 6

            if (sscanf(line, "%s %s %s %s %s %s %s %s %s", rule_name, direction_str, src_ip_str, 
                dst_ip_str, protocol_str, src_port_str, dst_port_str, ack_str, action_str) != 9) 
                    error_fclose_file(file, "load_rules")
            

            direction = parse_direction(direction_str);
            if (direction < 0) error_fclose_file(file, "direction")

            src_ip = parse_ip_addr(src_ip_str);
            if (src_ip < 0) error_fclose_file(file, "source ip")
            parsed_src_ip = htonl(src_ip);

            src_prefix_size = parse_mask(src_ip_str);
            if (src_prefix_size < 0) error_fclose_file(file, "source ip mask")

            dst_ip = parse_ip_addr(dst_ip_str);
            if (dst_ip < 0) error_fclose_file(file, "dest ip")
            parsed_dst_ip = htonl(dst_ip);

            dst_prefix_size = parse_mask(dst_ip_str);
            if (dst_prefix_size < 0) error_fclose_file(file, "dest ip mask")

            protocol = parse_protocol(protocol_str);
            if (protocol < 0) error_fclose_file(file, "protocol")

            src_port = parse_port(src_port_str);
            if (src_port < 0) error_fclose_file(file, "source port")
            parsed_src_port = htons(src_port);

            dst_port = parse_port(dst_port_str);
            if (dst_port < 0) error_fclose_file(file, "dest port")
            parsed_dst_port = htons(dst_port);

            ack = parse_ack(ack_str);
            if (ack < 0) error_fclose_file(file, "ack")

            action = parse_action(action_str);
            if (action < 0) error_fclose_file(file, "action")

            sprintf(parsed_line, "%s %u %u %hhu %u %hhu %hhu %hu %hu %u %hhu\n", rule_name, direction, 
            parsed_src_ip, src_prefix_size, parsed_dst_ip, dst_prefix_size, protocol, parsed_src_port, 
            parsed_dst_port, ack, action);

            strcat(res, parsed_line);
        } 

        fclose(file);
        //print_to_device(path, res);
        device = popen("sudo tee /sys/class/fw/rules/rules > /dev/null", "w");      //writing to device requires root permissions
        if (!device) error_occured("popen rules failed")
        fprintf(device, "%s", res);
        pclose(device);
    }

    else 
    {   //argc = 2
        
        if (!strcmp(argv[1], "show_rules")) 
        {
            //showing rules
            path = "/sys/class/fw/rules/rules";
            device = fopen(path, "r");
            if (!device) error_occured("fopen failed")

            while (getline(&line, &len, device) != -1)
            {
                char rule_name[21];    
                unsigned int direction, src_ip, src_prefix_size, dst_ip, dst_prefix_size,
                             src_port, dst_port, protocol, ack, action;

                if (sscanf(line, "%s %u %u %u %u %u %u %u %u %u %u\n", rule_name, &direction, &src_ip, &src_prefix_size, 
                    &dst_ip, &dst_prefix_size, &protocol, &src_port, &dst_port, &ack, &action) != 11)
                        error_fclose_file(device, "error reading rules device")
                
                printf("%s ", rule_name);
                print_direction(direction);
                print_ip_with_mask(src_ip, src_prefix_size);
                print_ip_with_mask(dst_ip, dst_prefix_size);
                print_protocol(protocol);
                print_port(src_port);
                print_port(dst_port);
                print_ack(ack);
                print_action(action);
                printf("\n");
                
            }
            fclose(device);
        }

        else if (!strcmp(argv[1], "show_log")) 
        {
            //showing log
            device = popen("sudo cat /dev/fw_log", "r");
            if (!device) error_occured("fopen log file")

            struct tm tm_info;
            char time_str[20];
            unsigned long timestamp;
            unsigned int src_ip, dst_ip;
            unsigned short src_port, dst_port;
            int protocol, action, reason, count;
            printf("timestamp\t\t\tsrc_ip\t\t\tdst_ip\t\t\tsrc_port\tdst_port\t"
                "protocol\taction\treason\t\t\t\tcount\n");

            while (getline(&line, &len, device) != -1)
            {
                if (sscanf(line, "%lu %u %u %hu %hu %d %d %d %d\n", &timestamp, &src_ip, &dst_ip, 
                    &src_port, &dst_port, &protocol, &action, &reason, &count) != 9) 
                        error_pclose_file(device, "reading from log device")
                
                //convert timestamp to human readable format
                localtime_r((time_t *)&timestamp, &tm_info);
                strftime(time_str, sizeof(time_str), "%d/%m/%Y %X", &tm_info);

                printf("%s\t\t", time_str);
                print_ip(src_ip);
                printf("\t\t");
                print_ip(dst_ip);
                printf("\t\t");
                printf("%hu ", ntohs(src_port));
                printf("\t\t");
                printf("%hu ", ntohs(dst_port));
                printf("\t\t");
                switch (protocol)
                {
                case 1:
                    printf("icmp\t\t");
                    break;
                
                case 6:
                    printf("tcp\t\t");
                    break;

                case 17:
                    printf("udp\t\t");
                    break;
                
                default:        //should not reach this
                    printf("other\t\t");
                    break;
                }
                print_action(action);
                printf("\t");
                print_reason(reason);
                printf("%d\n", count);
            }
            pclose(device);
        }

        else if (!strcmp(argv[1], "clear_log")) 
        {
            //clearing log
            path = "/sys/class/fw/log/reset";
            //print_to_device(path, "0");
            device = popen("sudo tee /sys/class/fw/log/reset > /dev/null", "w");
            if (!device) error_occured("popen log reset failed");
            fprintf(device, "0");
            pclose(device);
        }

        else error_occured("wrong input")
    }
    return 0;
}