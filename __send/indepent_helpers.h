#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <errno.h>
#include <stdbool.h>

#define ARGS_BUFFER_MAX_LEN 256
#define ARGS_BUFFER_OPTION_LEN 128
#define ARGS_BUFFER_VALUE_LEN 128

#define ARGS_BUFFER_MAX_LEN 256
#define ARGS_BUFFER_OPTION_LEN 128
#define ARGS_BUFFER_VALUE_LEN 128
#define MSG_BUFFER_LEN 128

struct arg_params {
    char machine_name[ARGS_BUFFER_VALUE_LEN];
    char if_names[3][ARGS_BUFFER_VALUE_LEN];
    uint32_t s_ip_addrs[3]; // inet_pton inet_ntop
    uint32_t d_ip_addrs[3];
    unsigned short s_ports[3];
    unsigned short d_ports[3];
    struct ether_addr s_mac_addrs[3]; // ether_ntoa_r ether_aton_r
    struct ether_addr d_mac_addrs[3];
};

struct arg_params *argps;

/**
 * @brief Parse options from stream. Invalid line will be reported and ignored.
 * Do not check if values are valid on this particular system (IP, hostname, ...)
 * 
 * @param arg_params 
 * @param fp 
 * @param delim 
 * @param comment_char 
 * @param quiet 
 * @return int Number of options that cannot be read. 0 means all options were read.
 */
int parse_params_from_stream(struct arg_params *arg_params, FILE *fp, char delim, 
                             char comment_char, uint8_t quiet)
{
    // TODO: trim spaces from option and value
    char options[][ARGS_BUFFER_OPTION_LEN] = {
                    "machine_name",
                    "if_name_local_0", "if_name_local_1", "if_name_local_2",
                    "ip_local_0", "ip_local_1", "ip_local_2",
                    "s_port_0", "s_port_1", "s_port_2",
                    "macaddr_local_0", "macaddr_local_1", "macaddr_local_2",
                    "ip_remote_0", "ip_remote_1", "ip_remote_2",
                    "d_port_0", "d_port_1", "d_port_2",
                    "macaddr_remote_0", "macaddr_remote_1", "macaddr_remote_2",

                    };
    int nbr_option = sizeof(options)/ARGS_BUFFER_OPTION_LEN;
    if (!quiet)
        printf("PARSE_OPTION: Number of options need to be read: %d\n", nbr_option);
    char buffer_option[ARGS_BUFFER_OPTION_LEN] = {0};
    char buffer_value[ARGS_BUFFER_VALUE_LEN] = {0};
    char buffer[ARGS_BUFFER_MAX_LEN] = {0};
    // Hold message to be printed out if error
    // Do not include newline char at the end!
    char msg_buff[MSG_BUFFER_LEN] = {0};
    int print_line = 0;     // if set, will print 'buffer' for debug

    uint8_t option_has_been_read[nbr_option];
    for (int i = 0; i < nbr_option; i++) {
        option_has_been_read[i] = 0;
    }

    while (fgets(buffer, ARGS_BUFFER_MAX_LEN, fp))
    {
        if (buffer[0] == comment_char  || buffer[0] == '\n')
            continue;
        // Remove trailing newline
        buffer[strcspn(buffer, "\n")] = 0;
        // split
        int str_len = strlen(buffer);
        int delim_index = -1;
        for (int i = 0; i < strlen(buffer); i++) {
            if (buffer[i] == delim) {
                if (delim_index != -1) {
                    print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Line with more than 1 delim: ");
                    goto clean_up;
                }
                delim_index = i;
            }
        }
        if (delim_index == -1) {
            print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Line with no delim: ");
            goto clean_up;
        }
        strncpy(buffer_option, buffer, delim_index);
        strncpy(buffer_value, buffer + delim_index + 1, str_len - delim_index - 1);
        // printf("%s, %s\n", buffer_option, buffer_value);
        if (strlen(buffer_option) == 0 || strlen(buffer_value) == 0) {
            // printf("hhehe\n");
            print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Can't extract option or value from line: ");
            goto clean_up;
        }

        if (strcmp(buffer_option, "machine_name") == 0) {
            strncpy(arg_params->machine_name, buffer_value, ARGS_BUFFER_VALUE_LEN);
        } else if (strcmp(buffer_option, "if_name_local_0") == 0) {
            strncpy(arg_params->if_names[0], buffer_value, ARGS_BUFFER_VALUE_LEN);
        } else if (strcmp(buffer_option, "if_name_local_1") == 0) {
            strncpy(arg_params->if_names[1], buffer_value, ARGS_BUFFER_VALUE_LEN);
        } else if (strcmp(buffer_option, "if_name_local_2") == 0) {
            strncpy(arg_params->if_names[2], buffer_value, ARGS_BUFFER_VALUE_LEN);
        // TODO: refactor. Consider snprintf "ip_local_%d" and a for loop.
        // local_id
        } else if (strcmp(buffer_option, "ip_local_0") == 0) {
            struct in_addr inaddr;
            if (inet_pton(AF_INET, buffer_value, &inaddr) != 1) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure coverting IPv4 to binary: ");
                goto clean_up;
            }
            memcpy(&arg_params->s_ip_addrs[0], &inaddr, sizeof(uint32_t));
        } else if (strcmp(buffer_option, "ip_local_1") == 0) {
            struct in_addr inaddr;
            if (inet_pton(AF_INET, buffer_value, &inaddr) != 1) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure coverting IPv4 to binary: ");
                goto clean_up;
            }
            memcpy(&arg_params->s_ip_addrs[1], &inaddr, sizeof(uint32_t));
        } else if (strcmp(buffer_option, "ip_local_2") == 0) {
            struct in_addr inaddr;
            if (inet_pton(AF_INET, buffer_value, &inaddr) != 1) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure coverting IPv4 to binary: ");
                goto clean_up;
            }
            memcpy(&arg_params->s_ip_addrs[2], &inaddr, sizeof(uint32_t));
        // remote_ip
        } else if (strcmp(buffer_option, "ip_remote_0") == 0) {
            struct in_addr inaddr;
            if (inet_pton(AF_INET, buffer_value, &inaddr) != 1) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure coverting IPv4 to binary: ");
                goto clean_up;
            }
            memcpy(&arg_params->d_ip_addrs[0], &inaddr, sizeof(uint32_t));
        } else if (strcmp(buffer_option, "ip_remote_1") == 0) {
            struct in_addr inaddr;
            if (inet_pton(AF_INET, buffer_value, &inaddr) != 1) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure coverting IPv4 to binary: ");
                goto clean_up;
            }
            memcpy(&arg_params->d_ip_addrs[1], &inaddr, sizeof(uint32_t));
        } else if (strcmp(buffer_option, "ip_remote_2") == 0) {
            struct in_addr inaddr;
            if (inet_pton(AF_INET, buffer_value, &inaddr) != 1) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure coverting IPv4 to binary: ");
                goto clean_up;
            }
            memcpy(&arg_params->d_ip_addrs[2], &inaddr, sizeof(uint32_t));
        // local_port
         } else if (strcmp(buffer_option, "s_port_0") == 0) {
            long port = strtol(buffer_value, NULL, 10);
            const bool range_error = errno == ERANGE;
            if (port < 0 || port > 65535 || range_error) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure reading port number: ");
                goto clean_up;
            }
            arg_params->s_ports[0] = (unsigned short) port;
        } else if (strcmp(buffer_option, "s_port_1") == 0) {
            long port = strtol(buffer_value, NULL, 10);
            const bool range_error = errno == ERANGE;
            if (port < 0 || port > 65535 || range_error) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure reading port number: ");
                goto clean_up;
            }
            arg_params->s_ports[1] = (unsigned short) port;
        } else if (strcmp(buffer_option, "s_port_2") == 0) {
            long port = strtol(buffer_value, NULL, 10);
            const bool range_error = errno == ERANGE;
            if (port < 0 || port > 65535 || range_error) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure reading port number: ");
                goto clean_up;
            }
            arg_params->s_ports[2] = (unsigned short) port;
        // remote_port
         } else if (strcmp(buffer_option, "d_port_0") == 0) {
            long port = strtol(buffer_value, NULL, 10);
            const bool range_error = errno == ERANGE;
            if (port < 0 || port > 65535 || range_error) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure reading port number: ");
                goto clean_up;
            }
            arg_params->d_ports[0] = (unsigned short) port;
        } else if (strcmp(buffer_option, "d_port_1") == 0) {
            long port = strtol(buffer_value, NULL, 10);
            const bool range_error = errno == ERANGE;
            if (port < 0 || port > 65535 || range_error) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure reading port number: ");
                goto clean_up;
            }
            arg_params->d_ports[1] = (unsigned short) port;
        } else if (strcmp(buffer_option, "d_port_2") == 0) {
            long port = strtol(buffer_value, NULL, 10);
            const bool range_error = errno == ERANGE;
            if (port < 0 || port > 65535 || range_error) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure reading port number: ");
                goto clean_up;
            }
            arg_params->d_ports[2] = (unsigned short) port;
        // local_mac
        } else if (strcmp(buffer_option, "macaddr_local_0") == 0) {
            if (!ether_aton_r(buffer_value, &arg_params->s_mac_addrs[0])) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure coverting mac addr to binary: ");
                goto clean_up;
            }
        } else if (strcmp(buffer_option, "macaddr_local_1") == 0) {
            if (!ether_aton_r(buffer_value, &arg_params->s_mac_addrs[1])) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure coverting mac addr to binary: ");
                goto clean_up;
            }
        } else if (strcmp(buffer_option, "macaddr_local_2") == 0) {
            if (!ether_aton_r(buffer_value, &arg_params->s_mac_addrs[2])) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure coverting mac addr to binary: ");
                goto clean_up;
            }
        // dest_mac
        } else if (strcmp(buffer_option, "macaddr_remote_0") == 0) {
            if (!ether_aton_r(buffer_value, &arg_params->d_mac_addrs[0])) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure coverting mac addr to binary: ");
                goto clean_up;
            }
        } else if (strcmp(buffer_option, "macaddr_remote_1") == 0) {
            if (!ether_aton_r(buffer_value, &arg_params->d_mac_addrs[1])) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure coverting mac addr to binary: ");
                goto clean_up;
            }
        } else if (strcmp(buffer_option, "macaddr_remote_2") == 0) {
            if (!ether_aton_r(buffer_value, &arg_params->d_mac_addrs[2])) {
                print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Failure coverting mac addr to binary: ");
                goto clean_up;
            }

        } else {
            print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Not in any option: ");
            goto clean_up;
        }

        if (strlen(msg_buff) == 0) {
            // No error reading option. Add done to record
            for (int i = 0; i < nbr_option; i++) {
                if (strcmp(buffer_option, options[i]) == 0) {
                    option_has_been_read[i] = 1;
                    break;
                }
            } 
        }

        clean_up:
            if (!quiet && strlen(msg_buff) > 0) {
                printf("PARSE_OPTION: %s", msg_buff);
                printf("\"%s\"\n", print_line ? buffer : "");
            }
            memset(buffer_option, 0, ARGS_BUFFER_OPTION_LEN);
            memset(buffer_value, 0, ARGS_BUFFER_VALUE_LEN);
            memset(msg_buff, 0, MSG_BUFFER_LEN);
            memset(buffer, 0, ARGS_BUFFER_MAX_LEN);
            print_line = 0;
    }
    // Check if all options were successfully read 
    int count_unread = 0;
    for (int i = 0; i < nbr_option; i++) {
        if (option_has_been_read[i]) {
            continue;
        }
        printf("... failed to read option '%s' from input\n", options[i]);
        count_unread++;
    }
    return count_unread;
}


int test_arg_params(void)
{
    struct arg_params *argps = malloc(sizeof(struct arg_params));
    FILE *fp;
    fp = fopen("cmd_args.conf", "r");
    if (fp == NULL) {
      perror("Failed: ");
      return 1;
    }

    int ret = parse_params_from_stream(argps, fp, '=', '#', 0);
    printf("count_unread: %d\n", ret);
    printf("argps->machine_name: %s\n", argps->machine_name);
    for (int port_th = 0; port_th < 3; port_th++) {
        printf("#####################################\n");
        printf("argps->if_names[%d]: %s\n", port_th, argps->if_names[port_th]);
        printf("argps->s_ip_addrs[%d]: 0x%.8x\n", port_th, argps->s_ip_addrs[port_th]);
        printf("argps->s_ports[%d]: %d\n", port_th, argps->s_ports[port_th]);
        printf("argps->d_ip_addrs[%d]: 0x%.8x\n", port_th, argps->d_ip_addrs[port_th]);
        printf("argps->d_ports[%d]: %d\n", port_th, argps->d_ports[port_th]);
        printf("argps->s_mac_addrs[%d]: ", port_th);
        // TODO: extract this macaddr printing function 
        for (int i = 0; i < sizeof(argps->s_mac_addrs[port_th].ether_addr_octet); i++) {
            printf("%02X", argps->s_mac_addrs[port_th].ether_addr_octet[i]);
            printf("%c", i == sizeof(argps->s_mac_addrs[port_th].ether_addr_octet) - 1 ? '\n' : ':');
        }
        printf("argps->d_mac_addrs[%d]: ", port_th);
        for (int oct_th = 0; oct_th < sizeof(argps->d_mac_addrs[port_th].ether_addr_octet); oct_th++) {
            printf("%02X", argps->d_mac_addrs[port_th].ether_addr_octet[oct_th]);
            printf("%c", oct_th == sizeof(argps->d_mac_addrs[port_th].ether_addr_octet) - 1 ? '\n' : ':');
        }
    }
    free(argps);
    fclose(fp);
    return 0;
}
