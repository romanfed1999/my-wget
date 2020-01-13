#define _GNU_SOURCE

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>

#define ENABLE_DEBUG
#define MAX_PACKET_SIZE 2048

struct addrinfo hints, *infoptr;

char* get_http_header(char **raw_data)
{
    char *p, *header;

    p = (char*) memmem(*raw_data, MAX_PACKET_SIZE, "\r\n\r\n", 4);
    if (p)
    {
        *(p + 3) = '\0';
        p += 4;
        header = malloc(strlen(*raw_data) + 1);
        if (!header)
            return NULL;
        strcpy(header, *raw_data);
        *raw_data = p;
        return header;
    }
    else
        return NULL;
}

char* receive_http_header(int network_socket, char **leftover_data,
        int *leftover_data_size)
{
    char *response, *p, *http_header;
    int total_received_bytes, received_bytes;

    response = p = malloc(MAX_PACKET_SIZE);
    if (!p)
        return NULL;

    total_received_bytes = 0;
    received_bytes = recv(network_socket, response, MAX_PACKET_SIZE, 0);
    if (received_bytes < 0)
    {
        puts("recv failed");
        return NULL;
    }
    total_received_bytes += received_bytes;
    http_header = get_http_header(&response);
    if (http_header)
    {
#ifdef ENABLE_DEBUG
        printf("%s", http_header);
#endif
        *leftover_data_size = received_bytes - strlen(http_header) - 1;
        *leftover_data = malloc(*leftover_data_size);
        if (!(*leftover_data))
        {
            free(p);
            return NULL;
        }
        memcpy(*leftover_data, response, *leftover_data_size);
        free(p);
    }
    else
        puts("Http header is NULL");
    return http_header;
}

int get_http_response(char *http_header)
{
    int http_response;
    char *ptr = http_header;

    ptr = strstr(ptr, "HTTP/");
    if (ptr)
    {
        sscanf(ptr, "%*s %d", &http_response);
    }
    else
    {
        http_response = -1;
    }
    return http_response;
}

int get_content_length(char *http_header)
{
    int content_length;
    char *ptr = http_header;
    ptr = strstr(ptr, "Content-Length:");
    if (ptr)
    {
        sscanf(ptr, "%*s %d", &content_length);
    }
    else
    {
        content_length = -1;
    }

    return content_length;
}

int get_ip_from_domain(char *domain, char *ip_buffer, size_t ip_buffer_size)
{
    int getaddrinfo_result, getnameinfo_result;

    getaddrinfo_result = getaddrinfo(domain, NULL, &hints, &infoptr);
    if (getaddrinfo_result)
    {
#ifdef ENABLE_DEBUG
        printf("getaddrinfo: %s\n", gai_strerror(getaddrinfo_result));
#endif
        return -1;
    }

    getnameinfo_result = getnameinfo(infoptr->ai_addr, infoptr->ai_addrlen,
            ip_buffer, ip_buffer_size, NULL, 0, NI_NUMERICHOST);
    if (getnameinfo_result == 0)
        return -1;
#ifdef ENABLE_DEBUG
    puts(ip_buffer);
#endif
    return 0;
}

int connect_socket(int *network_socket, char *ip)
{
    int connect_result;
    struct sockaddr_in server_address;

    *network_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (*network_socket == -1)
    {
        puts("Error while creating socket");
        return -1;
    }
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(80);
    server_address.sin_addr.s_addr = inet_addr(ip);

    connect_result = connect(*network_socket,
            (struct sockaddr*) &server_address, sizeof(server_address));
    return connect_result;
}

int send_get_request(int network_socket, char *domain, char *remote_file_path)
{
    int send_result;
    char GET_data_frame[] = "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n";
    size_t GET_data_size = strlen(domain) + strlen(remote_file_path)
            + strlen(GET_data_frame) + 1;
    char *GET_data = malloc(GET_data_size);
    if (!GET_data)
        return -1;
    snprintf(GET_data, GET_data_size, GET_data_frame, remote_file_path, domain);

    send_result = send(network_socket, GET_data, GET_data_size, 0);
    if (send_result < GET_data_size)
        send_result = -1;

    return send_result;
}

int process_server_response(int network_socket, char *file_name)
{
    char *leftover_response_data, *http_header;
    int http_response, response_data_size, total_received_bytes;
    int file_size, file_numwritten;
    FILE *file;

    http_header = receive_http_header(network_socket, &leftover_response_data,
            &response_data_size);
    if (!http_header)
        return -1;

    http_response = get_http_response(http_header);
    if (http_response != 200)
    {
        puts("Wrong http response_data");
#ifdef ENABLE_DEBUG
        printf("http response: %d\n", http_response);
#endif
        return -1;
    }
    file_size = get_content_length(http_header);

    file = fopen(file_name, "wb");
    if (file == NULL)
    {
        puts("Error while trying to open a file");
#ifdef ENABLE_DEBUG
        puts("File name:");
        puts(file_name);
#endif
        return -1;
    }

    file_numwritten = fwrite(leftover_response_data, response_data_size, 1,
            file);
    if (file_numwritten != 1)
    {
        puts("Error while trying to write leftover data to a file");
#ifdef ENABLE_DEBUG
        puts("File name:");
        puts(file_name);
#endif
        fclose(file);
        return -1;
    }
    free(leftover_response_data);

    char *response_data = malloc(sizeof(char) * MAX_PACKET_SIZE);
    total_received_bytes = response_data_size;

    while (1)
    {
        int received_bytes;

        if (total_received_bytes >= file_size)
        {
            puts("Completed");
#ifdef ENABLE_DEBUG
            printf("Finished, received %d bytes out of %d\n",
                    total_received_bytes, file_size);
#endif
            free(response_data);
            break;
        }

        if (file_size - total_received_bytes > MAX_PACKET_SIZE)
        {
            received_bytes = recv(network_socket, response_data,
            MAX_PACKET_SIZE, 0);
        }
        else
        {
            received_bytes = recv(network_socket, response_data,
                    file_size - total_received_bytes, 0);
        }
        if (received_bytes < 0)
        {
            puts("Receiving failed");
            break;
        }
        total_received_bytes += received_bytes;

        file_numwritten = fwrite(response_data, received_bytes, 1, file);
        if (file_numwritten != received_bytes)
        {
            puts("Error while trying to write to a file");
#ifdef ENABLE_DEBUG
            puts("File name:");
            puts(file_name);
#endif
            return -1;
        }
    }

    if (fclose(file) != 0)
    {
        puts("Error while trying to close a file");
#ifdef ENABLE_DEBUG
                    puts("File name:");
                    puts(file_name);
#endif
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    char *file_name, *domain, *remote_file_path, ip[250];
    int network_socket, send_get_request_result, process_server_response_result;

    if (argc >= 4)
    {
        domain = argv[1];
        remote_file_path = argv[2];
        file_name = argv[3];
    }
    else
    {
        exit(1);
    }

    if (!get_ip_from_domain(domain, ip, 250))
    {
        puts("IP error");
        return 0;
    }

    if (connect_socket(&network_socket, ip) != 0)
    {
        puts("Error connecting socket");
#ifdef ENABLE_DEBUG
        puts("IP:");
        puts(ip);
#endif
        exit(1);
    }

    send_get_request_result = send_get_request(network_socket, domain,
            remote_file_path);
    if (send_get_request_result == -1)
    {
        puts("Error transmitting data");
        exit(1);
    }

    process_server_response_result = process_server_response(network_socket,
            file_name);
    if (process_server_response_result == -1)
        puts("Error while receiving file");

    return 0;
}
