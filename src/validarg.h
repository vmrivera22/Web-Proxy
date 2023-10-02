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

#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <math.h>

using namespace std;

bool dig_check(char*);
int port_v_check(char*);
bool port_bool_check(char*);

bool dig_check(char *a){
    int len_a = strlen(a);
    for(int i = 0; i < len_a; i+=1){
        if(isdigit(a[i]) == false){
            return false;
        }
    }
    return true;
}

// Function checks if a port is valid, if it is not then it exits.
int port_v_check(char *s_port){
    if(s_port == NULL){
        cerr << "No port was entered.\n\n";
        exit(-1);
    }
    bool dig_p = dig_check(s_port);
    if(dig_p == false){
        cerr << "Port input is not valid.\n\n";
        exit(-1);
    }
    int port_in = atoi(s_port);
    if(port_in > 65536 || port_in < 1025){
        cerr << "Port out of acceptable range. Port has to be between 1025 and 65536.\n\n";
        exit(-1);
    }
    return port_in;
}

// This function checks if a port is valid and returns a false if it is not and true if it is.
bool port_bool_check(char *s_port){
    if(s_port == NULL){
        cerr << "No port was entered.\n\n";
        return false;
    }
    bool dig_p = dig_check(s_port);
    if(dig_p == false){
        cerr << "Port input is not valid.\n\n";
        return false;
    }
    int port_in = atoi(s_port);
    if(port_in > 65536 || port_in < 1025){
        cerr << "Port out of acceptable range. Port has to be between 1025 and 65536.\n\n";
        return false;
    }
    return true;
}
//date_format client_ip request_first_line http_status_code response_size_in_byte
int format_time(char *buff, char *IP_cli, char *line_first, char *status_code, char *size_of_response){
    time_t curr_time;
    struct timeval time_mil;
    struct tm *gm_curr_time;
    gettimeofday(&time_mil, NULL);
    time(&curr_time);
    int millisec = lrint(time_mil.tv_usec/1000.0); // Round to nearest millisec
    if (millisec>=1000) { // Allow for rounding up to nearest second
        millisec -=1000;
        time_mil.tv_sec++;
    }

    gm_curr_time = gmtime(&curr_time);
    strftime(buff, 100, "%Y-%m-%dT%H:%M:%S", gm_curr_time);

    int len_time = strlen(buff);
    char *temp = new char[200]{'\0'};
    memcpy(temp, buff, len_time);

    memset(buff, '\0', 100);
    sprintf(buff, "%s.%03d", temp, millisec);
    delete[] temp;
    len_time = strlen(buff);

    const char* z = "Z ";
    memcpy(buff+len_time, z, 2);
    len_time += 2;
    //////////////////time_end//////////////////
    memcpy(buff+len_time, IP_cli, strlen(IP_cli));
    len_time += strlen(IP_cli);
    const char* com_space = " ";
    memcpy(buff+len_time, com_space, 1);
    len_time += 1;
    buff[len_time] = '\"';
    len_time += 1;

    memcpy(buff+len_time, line_first, strlen(line_first));
    len_time += strlen(line_first);

    buff[len_time] = '\"';
    len_time += 1;

    buff[len_time] = ' ';
    len_time += 1;

    memcpy(buff+len_time, status_code, strlen(status_code));
    len_time += strlen(status_code);
    buff[len_time] = ' ';
    len_time += 1;

    memcpy(buff+len_time, size_of_response, strlen(size_of_response));
    len_time += strlen(size_of_response);

    buff[len_time] = '\n';
    len_time += 1;

    //cout << buff << "\n";
    

    return len_time;
}
