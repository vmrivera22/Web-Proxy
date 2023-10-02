Victor Rivera

Sources Used:
    For this program I referenced Professor Parsa's lectures. In particularly lecture openssl_2up.pdf lecture. I also referenced code I had previously written for other classes and the previous assignmnets for this class (lab 1 and Lab 4). I also used both man pages and geeksforgeeks to figure out how some functions worked. Additionally I got help from the TA Yi Liu and the tutor Sammy. I used a Linked List that I had previously written for CSE 101 modified to work for the assignment. I used https://www.youtube.com/watch?v=xoXzp4B8aQk&list=PLfqABt5AS4FmuQf70psXrsMLEDQXNkLq2&index=5 (CodeVault video) and https://www.youtube.com/watch?v=Pg_4Jz8ZIH4 (Jacob Sorber Video) to make threads. 


Within the top directroy of this project there are three sub directories: bin, src, and doc.

Files: This project contains the following files:
At the top level: Makefile, README.md
In the src dir: myproxy.cpp, validarg.h, and ll.h
In the doc dir: tests.txt
In the bin dir: {empty}


How to run the program:
    To make an executable of the program type make within the top directory.
    Start the proxy using the command:
    "./bin/myproxy listen_port forbidden_sites_file_path access_log_file_path"

    listen_port: The port on which the proxy should listen on.
    forbidden_sites_file_path: The file that contains the list of forbidden sites.
    access_log_file_path: The file that keeps a log of requests that were sent to the proxy.

    After the proxy is started reroute a http get request from a browser or curl to the proxy. Example: curl -x http://127.0.0.1:65000/ http://www.example.com.
    Where 127.0.0.1 is the IP address of the machine running the proxy and 65000 is the port the proxy is listening on.

    Note that if the indicated access_log_file_path does not exists then it will be created.

    Ctrl c is used to refresh the access_log_file.

Makefile:
    The Makefile is used to create an executable of the program. To make an executable, use the command "make" within the same directory as the Makefile.
    This will create the executable "myproxy" within the bin folder. Run the proxy using "./bin/myproxy listen_port forbidden_sites_file_path access_log_file_path".

    The executable can be removed using the command "make clean" in the same directory as the Makefile.

README.md:
    This file is the README. It contains a description of the files within the program, descriptions of the program itself, and citations to code referenced.

myproxy.cpp:
    This file is the file that contains the code for the proxy. The program takes 3 arguments and is ran using:
    "./bin/myproxy listen_port forbidden_sites_file_path access_log_file_path".

    listen_port: The port on which the proxy should listen on.
    forbidden_sites_file_path: The file that contains the list of forbidden sites.
    access_log_file_path: The file that keeps a log of requests that were sent to the proxy.

    The purpose of this program is to accept TCP connections from clients and recive HTTP GET requests from said clients. Based on the HTTP request the proxy sets up a SSL connection to the server the client intended the GET request to go. The request is then sent to the server using this SSL connection. The proxy then recives the response to the GET request and returns the response to the client.

validarg.h:
    This header file contains functions that are mainly used to check the validity of the input arguments. It also contains additional useful functions such as a function for formatting the log output.

ll.h: 
    This header file contains the linked list class and functions corresponding to the linked list. This is used in order to store the forbidden sites.

tests.txt:
    This file contains 5 tests that I ran to test the functionality of the server and client.

