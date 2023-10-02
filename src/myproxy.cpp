// Proxy
#include <iostream>
#include <string>
#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <array>
#include <sstream>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <vector>
#include <cmath>
#include <string>

#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <atomic>
#include "validarg.h"
#include "ll.h"

#define FORBIDDEN_N 0
#define CONNECT_N 1
#define GATE_N 2
#define BAD_N 3

using namespace std;

int listen_socke;
pthread_mutex_t m;


char **forbidden_file;
char *fo_file_name;

LinkedList forbidden_file_list;

atomic<long> version( 0 );

bool made = false;

// Function used to find the path of a file.
char* find_file(char *&out_file){
    try{
        string ret = out_file;
        size_t place = ret.find_last_of("/");
        if (place == string::npos){
            return NULL;
        }
        string path_temp = ret.substr(0, place);
        char *c_path_temp = strdup(path_temp.c_str());

        path_temp = ret.substr(place+1);
        out_file = strdup(path_temp.c_str());

        return c_path_temp;
    }
    catch(...){
        cerr << "ERROR getting the file path.\n\n";
        exit(-1);
    }
}

// Function used to make file path if it does not exist.
void mk_all_dir(char *fi_path){
    try{
        made = true;
        string h = "";
        string sla = "/";
        char *c_sla = strdup(sla.c_str());
        char *all = strdup(h.c_str());
        char *temp = strtok(fi_path, "/");
        all = strcat(all, temp);
        mkdir(all, 777);
        while(temp != NULL){
            temp = strtok(NULL, "/");
            if(temp == NULL){
                break;
            }
            all = strcat(all, c_sla);
            all = strcat(all, temp);
            mkdir(all, 777);   
        }
        return;
    }
    catch(...){
        cerr << "ERROR making output directories.\n\n";
        exit(-1);
    }
}

// Class that is passed into the threads as an argument.
class thread_arg{
    public:
        int thread_socket = 0;
        const SSL_METHOD* meth;
        char *output_file;
};

// Function used to read the forbidden file into a linked list.
void read_forbidden_list(){
    forbidden_file_list.deleteList();
    ifstream file_forbidden;
    file_forbidden.open(fo_file_name, ios::binary);
    if(file_forbidden.is_open() == false){
        cerr << "Error opening forbidden sites file.\nMake sure that the file exists.\n";
        exit(-1);
    }
    string line;
    while(getline(file_forbidden, line)){
        char *c_line = strdup(line.c_str());
        forbidden_file_list.insert(c_line);
    }
    file_forbidden.close();
}

// Function used to catche Ctrl C signal
void c_sig(int dummy) {
    pthread_mutex_lock(&m);
    //int old = forbidden_file_list.length();
    //cout << "Old: " << old << "\n";
    read_forbidden_list();
    //int new_size = forbidden_file_list.length();
    //cout << "New: " << new_size << "\n";
    version += 1;
    pthread_mutex_unlock(&m);
    return;
}

// Function used to catch SIGPIPE signal (so that the program is not terminated).
void pipe_sig(int dummy){
    cerr << "Broken Pipe. Host (client) became unreachable.\n";
    return;
}

// Function makes the 403 forbidden response.
void make_Forbidden(char *err_response){
    const char *temp = "HTTP/1.1 403 Forbidden\r\n\r\n";
    memcpy(err_response, temp, 26);
    return;
}

// Function makes the 501 Not implemented response.
int make_Connect(char *err_response){
    const char *temp = "HTTP/1.1 501 Not implemented\r\n\r\n";
    memcpy(err_response, temp, 32);
    return strlen(temp);
}

int make_Gate(char *err_response){
    const char *temp = "HTTP/1.1 504 Gateway Timeout\r\n\r\n";
    memcpy(err_response, temp, 32);
    return strlen(temp);
}

int make_Bad(char *err_response){
    const char *temp = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
    memcpy(err_response, temp, 28);
    return strlen(temp);
}

void err_hand(int type, int in_socket, char *from_IP_c, char *f_line_req, char *outfile_fun){
    char *err_res = new char[40]{'\0'};
    string err_cod;
    string num_size;
    if(type == GATE_N){
        make_Gate(err_res);
        cerr << "504 Gateway Timeout.\n";
        err_cod = "504";
        num_size = "32";
    }
    else if(type == CONNECT_N){
        make_Connect(err_res);
        cerr << "501 Not implemented.\n";
        err_cod = "501";
        num_size = "32";
    }
    else if(type == FORBIDDEN_N){
        make_Forbidden(err_res);
        cerr << "403 Forbidden.\n";
        err_cod = "403";
        num_size = "26";
    }
    else if(type == BAD_N){
        make_Bad(err_res);
        cerr << "502 Bad Gateway";
        err_cod = "502";
        num_size = "28";
    }
    int w_err = send(in_socket, err_res, 32, 0);
    if(w_err < 0){
        cerr << "Error sneding response to the client.\n";
    }
    delete[] err_res;
    //close(in_socket);
    if(made == false){
        char *out_file_save = outfile_fun;
        char *file_path = find_file(out_file_save);
        if(file_path != NULL){
            mk_all_dir(file_path);
        }
    }
    FILE *log_file;
    log_file = fopen(outfile_fun, "ab");
    char *time_buff = new char[1000]{'\0'};
    int time_size = format_time(time_buff, from_IP_c, f_line_req, strdup(err_cod.c_str()), strdup(num_size.c_str()));
    fwrite(time_buff, 1, time_size, log_file);
    fclose(log_file);
    delete[] time_buff;
    return;
}

int decrement_count(int curr, int by, bool n_chunked){
    if(n_chunked == true){
        return curr -= by;
    }
    else{
        return curr;
    }
}

int find_size_head(char *block){
    char *state = new char[10000]{'\0'};
    char *hold = new char[10000]{'\0'};
    memcpy(state, block, strlen(block));
    memcpy(hold, block, strlen(block));
    char *body = strstr(state, "\r\n\r\n");
    if(body == NULL){
        return 0;
    }
    int leng_body = strlen(body);
    int head_len = strlen(hold) - leng_body;
    delete[] hold;
    delete[] state;
    //cout << "Head_len: " << head_len << "\n";
    if(head_len < 31){
        return 0;
    }
    return head_len + 4;
}

void *thread_handler(void *arg){
    thread_arg in_argument = *(thread_arg*)arg;
    int t_socket = in_argument.thread_socket; // Client Socket.
    char *read_buff = new char[10000]{'\0'};  // Buffer that is used to read.
    char *h_read_buff = new char[10000]{'\0'}; // Buffer used to hold the request.
    char *read_buff_temp = new char[10000]{'\0'};
    //char *transfer_buff = new char[10000]{'\0'};
    int buff_size = 10000;
    int read_num = 1;

    struct addrinfo hints;
    struct addrinfo *results;

    struct sockaddr_in full_client_addr;
    socklen_t len = sizeof(full_client_addr);

    // Read the request from the client (do not expect more then 10,000 characters)
    read_num = recv(t_socket, read_buff, buff_size, 0);
    if(read_num == -1){
        cerr << "Error reading from Socket.\n";
        close(t_socket);
        pthread_exit(NULL);
    }
    // Make a copy of the request.
    memcpy(h_read_buff, read_buff, 10000);
    memcpy(read_buff_temp, read_buff, 10000);

    // Get the IP address of the client.
    int peer_err = getpeername(t_socket, (struct sockaddr *) &full_client_addr, &len);
    if(peer_err != 0){
        cerr << "ERROR getting Client IP.\n";
        close(t_socket);
        pthread_exit(NULL);
    }
    char *from_IP_c = inet_ntoa(full_client_addr.sin_addr);

    // Variables used to parse the header.
    char *parsed;
    char *saved = read_buff;
    char *t_host = new char[1000]{'\0'};
    char *parsed_port = NULL;
    char *t_parsed_port = NULL;
    int first = 0;
    char *f_line_req = new char[1000]{'\0'};
    char *f_line_req_copy = new char[1000]{'\0'};

    // Parse the request to get port and host.
    while((parsed = strtok_r(saved, "\n", &saved))){
        if(first == 0){
            memcpy(f_line_req, parsed, strlen(parsed)-1);
            char *port_state = parsed;
            t_parsed_port = strstr(port_state, "http");
            t_parsed_port = strstr(port_state, "HTTP");
            if(t_parsed_port){
                parsed_port = strtok_r(port_state, ":", &port_state);
                parsed_port = strtok_r(port_state, ":", &port_state);
                parsed_port = strtok_r(port_state, "/ ", &port_state);
            }
            else{
                parsed_port = strtok_r(port_state, ":", &port_state);
                parsed_port = strtok_r(port_state, "/ ", &port_state);
            }
        }
        first = 1;

        char *find_host = strstr(parsed, "Host: ");
        if(find_host){ // Find the host from the host line.
            char *host = find_host;
            t_host = strtok_r(host, " ", &host);
            t_host = strtok_r(host, ":\t\r\n", &host);
            break;
        }
    }

    memcpy(f_line_req_copy, f_line_req, 1000); // Keep a copy of the first line of the client request to output to the log.
    char *URL_pos = f_line_req_copy;
    char* URL = strtok_r(URL_pos, " ", &URL_pos);
    URL = strtok_r(URL_pos, " ", &URL_pos); // Gets the URL from the first line of the get request.

    //char *con = strstr(read_buff_temp, "CONNECT "); // Check the first line to make sure that it is not a CONNECT request.
    char *ge = strstr(read_buff_temp, "GET ");
    char *he = strstr(read_buff_temp, "HEAD ");
    if((ge == NULL) && (he == NULL)){
        pthread_mutex_lock(&m);
        err_hand(CONNECT_N, t_socket, from_IP_c, f_line_req, in_argument.output_file);
        pthread_mutex_unlock(&m);
        close(t_socket);
        pthread_exit(NULL);
    }
    delete[] read_buff_temp;

    //cout << h_read_buff << "\n";

    const char *host_name = t_host;
    Node *f_n = NULL;


    f_n = forbidden_file_list.find(URL, NULL); // Check to see if the URL is in the forbidden list
    if(f_n != NULL){
        pthread_mutex_lock(&m);
        err_hand(FORBIDDEN_N, t_socket, from_IP_c, f_line_req, in_argument.output_file);
        pthread_mutex_unlock(&m);
        close(t_socket);
        pthread_exit(NULL);
    }
    int curr_ver = version.load();

    bzero(&hints, sizeof(struct addrinfo));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;    
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    string s_port;
    if(parsed_port == NULL){
        s_port = "443";
    }
    else{
        s_port = parsed_port;
    }
    const char *port = strdup(s_port.c_str());

    int s = getaddrinfo(host_name, port, &hints, &results); // Get the IP of the URL server
    if(s != 0){
        cerr << "Error getting host IP.\n";
        pthread_mutex_lock(&m);
        err_hand(BAD_N, t_socket, from_IP_c, f_line_req, in_argument.output_file);
        pthread_mutex_unlock(&m);
        close(t_socket);
        pthread_exit(NULL);
    }
    struct sockaddr_in *serv_addr;
    int serv_sock = 0;
    
    char *saved_IP;
    Node *IP_find = NULL;
    while(results != NULL){ // Use loop to check if IP exists in restricted addresses       
        serv_sock = socket(results->ai_family, results->ai_socktype, results->ai_protocol);
        if((serv_sock < 0) && (results->ai_next != NULL)){
            results = results->ai_next;
            continue;
        }
        else if(serv_sock < 0){
            cerr << "Error creating socket.\n";
            close(t_socket);
            pthread_exit(NULL);
        }
        serv_addr = (struct sockaddr_in *)results->ai_addr; 
        saved_IP = inet_ntoa((struct in_addr)serv_addr->sin_addr);
        if(saved_IP != NULL){
            IP_find = forbidden_file_list.find(saved_IP, NULL);
            if(IP_find != NULL){
                if(results->ai_next != NULL){ // Checks all availible IP to see if any of them are not forbidden.
                    results = results->ai_next;
                    continue;
                }
                else{ // If the IP is forbidden and there are no more IPs then send 403 Forbidden to the client.
                    pthread_mutex_lock(&m);
                    err_hand(FORBIDDEN_N, t_socket, from_IP_c, f_line_req, in_argument.output_file);
                    pthread_mutex_unlock(&m);
                    close(t_socket);
                    pthread_exit(NULL);
                }
            }
        }
        try{
            struct linger l;
            l.l_onoff  = 1;
            l.l_linger = 100;
            setsockopt(serv_sock, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
        }
        catch(...){
            cerr << "ERROR setting socket options.\n";
            exit(-1);
        }
        int conn_err = connect(serv_sock, results->ai_addr, results->ai_addrlen); // Create a TCP connection to the fonund server.
        if(conn_err == 0){
            break;
        }
        if(results->ai_next == NULL){
            if(conn_err != 0 || serv_sock < 0){
                cerr << "Error getting host IP.\n";
                pthread_mutex_lock(&m);
                err_hand(BAD_N, t_socket, from_IP_c, f_line_req, in_argument.output_file);
                pthread_mutex_unlock(&m);
                close(t_socket);
                pthread_exit(NULL);
            }
            break;
        }
        results = results->ai_next;
    }
    SSL_CTX *t_ctx = SSL_CTX_new(in_argument.meth);
    SSL *ssl = SSL_new(t_ctx);
    if(ssl == NULL){
        cerr << "Could not create ssl.\n";
        close(t_socket);
        pthread_exit(NULL);
    }
    int ssl_fd = SSL_set_fd(ssl, serv_sock); // Same socket or make a new one?
    if(ssl_fd == 0){
        cerr << "Error setting the file descriptor.\n";
        close(t_socket);
        pthread_exit(NULL);
    }
    SSL_set_tlsext_host_name(ssl, host_name);
    int ssl_c_err = SSL_connect(ssl);
    if(ssl_c_err != 1){
        int con_ssl_err = SSL_get_error(ssl, 0);
        if(con_ssl_err == SSL_ERROR_SSL){
            cerr << "SSL_ERROR_SSL\n";
        }
        if(ssl_c_err == SSL_ERROR_WANT_CONNECT){
            cerr << "SSL_ERROR_WANT_CONNECT\n";
        }
        cerr << "Error performing SSL connect. Server may not be accepting SSL connections to the specified port.\n";
        pthread_mutex_lock(&m);
        err_hand(GATE_N, t_socket, from_IP_c, f_line_req, in_argument.output_file);
        pthread_mutex_unlock(&m);
        close(t_socket);
        pthread_exit(NULL);
    }

    SSL_get_peer_certificate(ssl);
    SSL_CTX_set_verify(t_ctx, SSL_VERIFY_PEER, NULL);

    int write_b = SSL_write(ssl, h_read_buff, read_num);
    if(write_b < 0){
        cerr << "Error writing GET request to the server.\n";
        close(t_socket);
        pthread_exit(NULL);
    }
    int read_b = 1;
    char *status_code;
    int total_bytes_sent = 0;

    // Peek to get the status code and the content length
    char *cop_read = new char[10000]{'\0'};
    char *cop_read2 = new char[10000]{'\0'};
    int num_peek = SSL_peek(ssl, cop_read, 10000);
    if(num_peek < 0){
        cerr << "Error Reading from the socket.\n";
        pthread_exit(NULL);
    }
    memcpy(cop_read2, cop_read, 10000);

    char *pnt_cpy = cop_read;
    int times_num = 0;
    char *parsed_l;
    char *by_size;
    bool has_count = false;
    while((parsed_l = strtok_r(pnt_cpy, "\n", &pnt_cpy))){
        if(times_num == 0){
            char *parsed_state = parsed_l;
            status_code = strtok_r(parsed_state, " ", &parsed_state);
            status_code = strtok_r(parsed_state, " ", &parsed_state);
            times_num = 1;
        }
        char *find_size = strstr(parsed_l, "Content-Length");
        if(find_size){
            has_count = true;
            char *t_size = find_size;
            by_size = strtok_r(t_size, " ", &t_size);
            by_size = strtok_r(t_size, "\t\r\n", &t_size);
        }
    }
    char *hold_code = new char[20]{'\0'};
    memcpy(hold_code, status_code, strlen(status_code));
    delete[] cop_read;

    int copy_total_length;
    if(has_count == true){
        copy_total_length = atoi(by_size); 
    }
    else{
        copy_total_length = 10;
    }

    int head_size = find_size_head(cop_read2);
    if(head_size == 0){
        has_count = false;
    }
    else{
        copy_total_length += head_size;
    }

    while((read_b) > 0 && (copy_total_length > 0) ){
        int temp_ver = version.load();
        if(temp_ver != curr_ver){
            cerr << "Versions do not match.\n";
            curr_ver = temp_ver;
            Node *res_for = forbidden_file_list.find(URL, NULL);
            if(res_for != NULL){
                pthread_mutex_lock(&m);
                err_hand(FORBIDDEN_N, t_socket, from_IP_c, f_line_req, in_argument.output_file);
                pthread_mutex_unlock(&m);
                close(t_socket);
                pthread_exit(NULL);
            }
        }
        memset(read_buff, '\0', 10000);
        read_b = SSL_read(ssl, read_buff, 1000);
        if(read_b < 0){
            cerr << "Error reading from the server.\n";
            if(errno == ECONNREFUSED){
                cerr << "Server Unreachable.\nCannot detect server.\n";
            }
            if((errno == ECONNRESET) || (errno == ECONNABORTED) || (errno == EHOSTUNREACH) || (errno == EHOSTDOWN)){
                cerr << "Server terminated.\n";
                cerr << strerror(errno);
            }
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(serv_sock);
            errno = 0;
            pthread_exit(NULL);
        }
        //cout << "b: " << copy_total_length << "\n";
        copy_total_length = decrement_count(copy_total_length, read_b, has_count); // don't decrement count if chunked encoding
        //cout << "n: " << copy_total_length << "\n";
        int sent_num = send(t_socket, read_buff, read_b, 0);
        if(sent_num < 0){
            cerr << "Error writing to the client.\n";
            if(errno == ECONNREFUSED){
                cerr << "Client Unreachable.\nCannot detect client.\n";
            }
            if((errno == ECONNRESET) || (errno == ECONNABORTED) || (errno == EHOSTUNREACH) || (errno == EHOSTDOWN)){
                cerr << "Client terminated.\n";
                cerr << strerror(errno);
            }
            if(errno == EPIPE){
                cerr << "TCP Peer Unrechable. SIGPIPE ERROR.\nCannot detect Client.\n";
            }
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(serv_sock);
            errno = 0;
            pthread_exit(NULL);
        }
        total_bytes_sent += read_b;
    }

    // Output to Log
    pthread_mutex_lock(&m);
    if(made == false){
        char *out_file_save = in_argument.output_file;
        char *file_path = find_file(out_file_save);
        if(file_path != NULL){
            mk_all_dir(file_path);
        }
    }
    FILE *log_file;
    log_file = fopen(in_argument.output_file, "ab");
    char *time_buff = new char[1000]{'\0'};
    int time_size = 0;
    //if(has_count == true){ // This is for non chunked encoding
    //    time_size = format_time(time_buff, from_IP_c, f_line_req, hold_code, by_size);
    //}
    //else{
    string s_total_bytes = to_string(total_bytes_sent);
    char *c_total_bytes = strdup(s_total_bytes.c_str());
    time_size = format_time(time_buff, from_IP_c, f_line_req, hold_code, c_total_bytes);   
    //}
    fwrite(time_buff, 1, time_size, log_file);
    fclose(log_file);
    pthread_mutex_unlock(&m);
    delete[] time_buff;
    
    //cout << "\nz\n";
    delete[] read_buff;
    delete[] cop_read2;
    delete[] hold_code;
    delete[] h_read_buff;
    delete[] f_line_req_copy;
    delete[] f_line_req;
    close(t_socket);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(serv_sock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]){
    for(int b = 1; b <= 3; b+= 1){
        if(argv[b] == NULL){
            cerr << "Not all arguments were input.\n\n";
            exit(-1);
        }
    }
    char *listen_port;
    int num_listen_port;
    char *forbidden_sites;
    char *access_log;

    try{
        listen_port = argv[1];
        num_listen_port = port_v_check(listen_port); // Check if the listen port is valid.
        forbidden_sites = argv[2];
        fo_file_name = argv[2];
        access_log = argv[3];
    }
    catch(...){
        cerr << "Not all arguments were valid.\n";
        exit(-1);
    }
    
    listen_socke = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_socke == -1){
        cerr << "Error creating Socket.\n";
    }

    int enable = 1;
    int opt_err = setsockopt(listen_socke, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    if(opt_err != 0){
        cerr << "Error setting socket option.\n";
        exit(-1);
    }
    struct sockaddr_in listen_addr;
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(num_listen_port);
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int bind_err = bind(listen_socke, (struct sockaddr*) &listen_addr, sizeof(listen_addr));
    if(bind_err == -1){
        cerr << "Error binding listen socket.\n";
        exit(-1);
    }

    int num_backlog = 1000;
    int listen_err = listen(listen_socke, num_backlog);
    if(listen_err == -1){
        cerr << "Error listening.\n";
        exit(-1);
    }

    signal(SIGINT, c_sig);
    signal(SIGPIPE, pipe_sig);
    pthread_mutex_init(&m, NULL);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* t_meth = SSLv23_client_method();

    pthread_t thread_arr[10000];
    int *sock_arr = new int[10000]{-1};
    int r = 0;

    forbidden_file = new char*[1000];
    ifstream file_forbidden;
    try{
        file_forbidden.open(forbidden_sites, ios::binary);
        if(file_forbidden.is_open() == false){
            cerr << "Error opening forbidden sites file.\nMake sure that the file existst.\n";
            exit(-1);
        }
    }
    catch(...){
        cerr << "Error opening forbidden sites file.\nMake sure that the file existst.\n";
        exit(-1);
    }

    string line;
    while(getline(file_forbidden, line)){
        char *c_line = strdup(line.c_str());
        forbidden_file_list.insert(c_line);
    }
    file_forbidden.close();

    // Make all directories for the output log file path.
    if(made == false){
        char *out_file_save = access_log;
        char *file_path = find_file(out_file_save);
        if(file_path != NULL){
            mk_all_dir(file_path);
        }
    }

    for(;;){
        socklen_t len = sizeof(listen_addr);
        sock_arr[r] = accept(listen_socke, (struct sockaddr *) &listen_addr, &len); // Accept incomming connections
        //cout << "here: \n";
        try{
            struct linger l;
            l.l_onoff  = 1;
            l.l_linger = 100;
            setsockopt(sock_arr[r], SOL_SOCKET, SO_LINGER, &l, sizeof(l));
        }
        catch(...){
            cerr << "ERROR setting socket options.\n";
            exit(-1);
        }
        thread_arg *in_arg = new thread_arg[sizeof(thread_arg)];
        in_arg->thread_socket = sock_arr[r];
        in_arg->meth = t_meth;
        in_arg->output_file = access_log;
        int check_thr = pthread_create(&thread_arr[r], NULL, &thread_handler, (void *)in_arg); // Create a thread for each connection
        if(check_thr != 0){
            cerr << "Error creating threads.\n";
            exit(-1);
        }
        r += 1;
        if(r == 10000){
            r = 0;
        }
    }
    return 0;
}