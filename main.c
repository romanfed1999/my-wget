#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PACKET_SIZE 2048

struct addrinfo hints, *infoptr;

char* get_http_header(char **raw_data)
{
    char *p, *header;
    p = strstr(*raw_data, "\r\n\r\n");
    if (p)
    {
        *(p + 3) = '\0';
        p += 4;
        header = malloc(strlen(*raw_data) + 1);
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
    char *response, *p;
    response = p = malloc(MAX_PACKET_SIZE);
    int total_received_bytes = 0;
    int received_bytes = recv(network_socket, response, MAX_PACKET_SIZE, 0);
    total_received_bytes += received_bytes;
    if (received_bytes < 0)
    {
        puts("recv failed");
    }
    char *http_header = get_http_header(&response);
    if (http_header)
    {
        printf("%s", http_header);
        *leftover_data_size = received_bytes - strlen(http_header) - 1;
        *leftover_data = malloc(*leftover_data_size);
        memcpy(*leftover_data, response, *leftover_data_size);
        free(p);
    }
    else
        printf("Http header is NULL");
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
    printf("Content-Length: %d\n", content_length);

    return content_length;
}

void get_ip_from_domain(char *domain, char *ip_buffer, size_t ip_buffer_size)
{
    int getaddrinfo_result = getaddrinfo(domain, NULL, &hints, &infoptr);
    if (getaddrinfo_result)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(getaddrinfo_result));
        exit(1);
    }

    getnameinfo(infoptr->ai_addr, infoptr->ai_addrlen, ip_buffer,
            ip_buffer_size, NULL, 0, NI_NUMERICHOST);
    puts(ip_buffer);
}

int main(int argc, char **argv)
{
    char *file_name, *domain, *remote_file_path, ip[250];
    if (argc >= 4)
    {
        domain = argv[1];
        remote_file_path = argv[2];
        file_name = argv[3];
    }
    else
        exit(1);

    get_ip_from_domain(domain, ip, 250);
    int network_socket;

    network_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(80);
    server_address.sin_addr.s_addr = inet_addr(ip);

    int connect_result = connect(network_socket,
            (struct sockaddr*) &server_address, sizeof(server_address));
    if (connect_result == -1)
    {
        puts("Connection failed\n");
        exit(1);
    }
    puts("Connected");

    char GET_data_frame[] = "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n";
    size_t GET_data_size = strlen(domain) + strlen(remote_file_path)
            + strlen(GET_data_frame) + 1;
    char *GET_data = malloc(GET_data_size);
    snprintf(GET_data, GET_data_size, GET_data_frame, remote_file_path, domain);
    send(network_socket, GET_data, GET_data_size, 0);

    char *leftover_response_data, *http_header;
    int http_response, response_data_size, file_size;
    http_header = receive_http_header(network_socket, &leftover_response_data,
            &response_data_size);
    http_response = get_http_response(http_header);
    if (http_response != 200)
    {
        printf("Wrong http response_data: %d\n", http_response);
        exit(-1);
    }
    file_size = get_content_length(http_header);
    remove(file_name);
    FILE *file = fopen(file_name, "ab");
    fwrite(leftover_response_data, response_data_size, 1, file);
    free(leftover_response_data);
    char *response_data = malloc(sizeof(char) * MAX_PACKET_SIZE);
    int total_received_bytes = response_data_size;
    while (1)
    {
        if (total_received_bytes >= file_size)
        {
            printf("Finished, received %d bytes out of %d\n",
                    total_received_bytes, file_size);
            free(response_data);
            break;
        }
        int received_bytes;
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
        total_received_bytes += received_bytes;
        if (received_bytes < 0)
        {
            puts("recv failed");
            break;
        }
        fwrite(response_data, received_bytes, 1, file);
    }
    fclose(file);

    return 0;
}
