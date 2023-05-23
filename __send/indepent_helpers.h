#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ether.h>



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
    struct sockaddr_in s_addrs[3];
    uint32_t d_ip_addrs[3];
    struct ether_addr s_mac_addrs[3]; // ether_ntoa_r ether_aton_r
    struct ether_addr d_mac_addrs[3];
};


/**
 * @brief Parse options from stream. Invalid line will be reported and ignored.
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
    char options[][ARGS_BUFFER_OPTION_LEN] = {
                    "machine_name",
                    "if_name_local_0", "if_name_local_1", "if_name_local_2",
                    "ip_local_0", "ip_local_1", "ip_local_2",
                    "macaddr_local_0", "macaddr_local_1", "macaddr_local_2",
                    "ip_remote_0", "ip_remote_1", "ip_remote_2",
                    "macaddr_remote_0", "macaddr_remote_1", "macaddr_remote_2",

                    };
    int nbr_option = sizeof(options)/ARGS_BUFFER_OPTION_LEN;
    printf("Number of options: %d\n", nbr_option);
    char buffer_option[ARGS_BUFFER_OPTION_LEN] = {0};
    char buffer_value[ARGS_BUFFER_VALUE_LEN] = {0};
    char buffer[ARGS_BUFFER_MAX_LEN] = {0};
    // Hold message to be printed out if error
    // Do not include newline char at the end!
    char msg_buff[MSG_BUFFER_LEN] = {0};
    int print_line = 0;     // print also current line if set

    uint8_t option_has_been_read[nbr_option];
    for (int i = 0; i < nbr_option; i++) {
        option_has_been_read[i] = 0;
    }

    while (fgets(buffer, ARGS_BUFFER_MAX_LEN, fp))
    {
        if (buffer[0] == comment_char)
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
            print_line = snprintf(msg_buff, MSG_BUFFER_LEN, "Can't extract option or value: ");
            goto clean_up;
        }

        if (strcmp(buffer_option, "machine_name") == 0) {
            strncpy(arg_params->machine_name, buffer_value, strlen(buffer_value));
        } else if (strcmp(buffer_option, "if_name_local_0") == 0) {
            strncpy(arg_params->if_names[0], buffer_value, strlen(buffer_value));
        } else if (strcmp(buffer_option, "if_name_local_1") == 0) {
            strncpy(arg_params->if_names[1], buffer_value, strlen(buffer_value));
        } else if (strcmp(buffer_option, "if_name_local_2") == 0) {
            strncpy(arg_params->if_names[2], buffer_value, strlen(buffer_value));
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
                printf("%s", msg_buff);
                // printf("%s\n", buffer);
                printf("%s\n", print_line ? buffer : "");
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
        printf("... failed to read option '%s'.\n", options[i]);
        count_unread++;
    }
    return count_unread;
}


int test_arg_params(void)
{
    struct arg_params *file_arg_params = malloc(sizeof(struct arg_params));

    // printf("Number of options: %ld\n", sizeof(options)/ARGS_BUFFER_OPTION_LEN);
    FILE *fp;
    fp = fopen("cmd_args.env", "r");
    if (fp == NULL) {
      perror("Failed: ");
      return 1;
    }

    int ret = parse_params_from_stream(file_arg_params, fp, '=', '#', 0);
    printf("count_unread: %d\n", ret);
    printf("file_arg_params->machine_name: %s\n", file_arg_params->machine_name);
    for (int port_th = 0; port_th < 3; port_th++) {
        printf("file_arg_params->if_names[%d]: %s\n", port_th, file_arg_params->if_names[port_th]);
        printf("file_arg_params->s_ip_addrs[%d]: 0x%.8x\n", port_th,file_arg_params->s_ip_addrs[port_th]);
        printf("file_arg_params->d_ip_addrs[%d]: 0x%.8x\n", port_th,file_arg_params->d_ip_addrs[port_th]);
        printf("file_arg_params->s_mac_addrs[%d]: ", port_th);
        for (int i = 0; i < sizeof(file_arg_params->s_mac_addrs[port_th].ether_addr_octet); i++) {
            printf("%02X", file_arg_params->s_mac_addrs[port_th].ether_addr_octet[i]);
            printf("%c", i == sizeof(file_arg_params->s_mac_addrs[port_th].ether_addr_octet) - 1 ? '\n' : ':');
        }
        printf("file_arg_params->d_mac_addrs[%d]: ", port_th);
        for (int oct_th = 0; oct_th < sizeof(file_arg_params->d_mac_addrs[port_th].ether_addr_octet); oct_th++) {
            printf("%02X", file_arg_params->d_mac_addrs[port_th].ether_addr_octet[oct_th]);
            printf("%c", oct_th == sizeof(file_arg_params->d_mac_addrs[port_th].ether_addr_octet) - 1 ? '\n' : ':');
        }
    }
    free(file_arg_params);
    fclose(fp);
    return 0;
}
