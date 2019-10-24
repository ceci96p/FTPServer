#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "dir.h"
#include "usage.h"
#include "server.h"
#include "netbuffer.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <signal.h>
#include <ifaddrs.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <fcntl.h>

// Here is an example of how to use the above function. It also shows
// one how to get the arguments passed on the command line.

#define MAX_LINE_LENGTH 1024
int login = 0;
int dataSocket = -43;
int type = 0; //ascii = 0 & image = 1

static void handle_client(int fd);


int main(int argc, char *argv[]) {
    int i;

    if (argc != 2) { // Check the command line arguments
      usage(argv[0]);
      return -1;
    }
      run_server(argv[1], handle_client);// initialize server
    return 0;
}


static int ip_version(const char *src) { // check socket IP Version
    char buf[16];
    if (inet_pton(AF_INET, src, buf) == 1) {
        return 4;
    } else if (inet_pton(AF_INET6, src, buf) == 1) {
        return 6;
    }
    return -1;
} 


char *trimwhitespace(char *str){   // Trim leading space
    char *end;
  while(isspace((unsigned char)*str)) str++;

  if(*str == 0)  
    return str;

  end = str + strlen(str) - 1;  // Trim trailing space
  while(end > str && isspace((unsigned char)*end)) end--;

  end[1] = '\0';   // Write new null terminator character

  return str;
}

static void *get_in_addr(struct sockaddr *sa) { //Get 
  if (sa->sa_family == AF_INET)
    return &(((struct sockaddr_in*)sa)->sin_addr);
  else
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


void handlepassivemode(int fd,char* localIP,int p1, int p2){ // send IP and Port number to client for Passive Mode connection 
    char result[260];
    memset(result,'0',sizeof(result)); 
    int version = ip_version(localIP);

if(version == 4){ // for IPV4
     char p1_char[20];
     sprintf(p1_char, "%i", p1);

     char p2_char[20];
     sprintf(p2_char, "%i", p2);

     char *pp1 = p1_char;
     char *pp2 = p2_char;

    char *token;
    char *IPparts[10];
    int i = 0;

    memset(IPparts,'0',sizeof(IPparts));

    token = strtok(localIP, ".\r\n"); 

    while (token) {
        IPparts[i] = token;
        token = strtok(NULL, ".\r\n");
        i++;
    }
    char *h1 = IPparts[0];
    char *h2 = IPparts[1];
    char *h3 = IPparts[2];
    char *h4 = IPparts[3];

    strcpy(result, "227 - Entering Passive Mode(");
    strcat(result, h1);
    strcat(result, ",");
    strcat(result, h2);
    strcat(result, ",");
    strcat(result, h3);
    strcat(result, ",");
    strcat(result, h4);
    strcat(result, ",");
    strcat(result, pp1);
    strcat(result, ",");
    strcat(result, pp2);
    strcat(result, ")");
    strcat(result, "\r\n");

    send_string(fd,result);

}else if(version == 6){ // for IPV6
    int port_int = p1 * 256 + p2;
    char port_char[20];
    sprintf(port_char, "%i", port_int);
    char *port = port_char;

    strcpy(result, "229 - Entering Extended Passive Mode (|||");
    strcat(result, port);
    strcat(result, "|)");
    strcat(result, "\r\n");

    send_string(fd,result);
  }              
}

int handleRETR(char* inputFileName, int fd, int dataSocket) {// RETR -- gets a file from the server AND transfer to client side
  FILE*  targetFile;
    

  char cwd[MAX_LINE_LENGTH + 1] = {0}; 
  memset(cwd, 0, sizeof(cwd));
  getcwd(cwd,MAX_LINE_LENGTH + 1); //get current directory
  strcat(cwd, "/");
  strcat(cwd, inputFileName);//append slash to input name "/name"
  char final_dest[MAX_LINE_LENGTH + 1];//sizeof(cwd) + sizeof(dest)
  memset(final_dest,0, 1000);
  strcat(final_dest, cwd); //append dir path to file name

  targetFile = fopen(final_dest, "rb+"); //open file to send
    
  if(targetFile == NULL){
    send_string(fd, "550 - Requested action not taken. File unavailable: file does not exist\r\n");
    //send_string(fd, "227 - Requested action not taken. File unavailable: file does not exist\r\n");
    return 0;
  }

  send_string(fd, "125 - Data connection already open; transfer starting\r\n");

  unsigned char buffer[MAX_LINE_LENGTH];
  memset(buffer,0,sizeof(buffer));

   while (1) {
    int bytes_read = fread(buffer, 1, sizeof(buffer), targetFile); //store how many bytes were read in case buffer is not filled up 
    if (bytes_read == 0){ //if 0 bytes are read we are done
      // send_string(fd, "250 - Requested file action okay,completed\r\n");
      break;
    }

    if (bytes_read < 0) { //if bytes read is a negative number then we got an error
      send_string(fd,"451 - Requested action aborted; local error in processing\r\n"); 
      return 0;
    }
     void *p = buffer;

    while (bytes_read > 0) { // if we read a positive number of bytes then pass then to the socket precisely 
      int bytes_written = write(dataSocket, p, bytes_read);

      if (bytes_written <= 0) {
         send_string(fd,"451 - Requested action aborted; local error in processing\r\n"); 
         return 0;
      }
      bytes_read -= bytes_written;
      p += bytes_written;
    }
  } 
return 1;
}

static void sigchld_handler(int s) { //TODO check what this does?
  int saved_errno = errno;
  while(waitpid(-1, NULL, WNOHANG) > 0);
  errno = saved_errno;
}


int handlePASV( int fd ) { //Create socket for passive mode
  static int BACKLOG =10;
  int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_storage their_addr; // connector's address information
  socklen_t sin_size;
  struct sigaction sa;
  int yes = 1;
  char s[INET6_ADDRSTRLEN];
  int rv;

  struct sockaddr myAddr;

  memset(&hints, 0, sizeof hints);
  hints.ai_family   = AF_UNSPEC;   // use IPv4 or IPv6, whichever is available
  hints.ai_socktype = SOCK_STREAM; // create a stream (TCP) socket server
  hints.ai_flags    = AI_PASSIVE;  // use any available connection
    
  // Gets information about available socket types and protocols
  int goodbind = 1;
    while(goodbind) {
      if ((rv = getaddrinfo(NULL, "0", &hints, &servinfo)) != 0) {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
      exit(1);
      } 
     // loop through all the results and bind to the first we can
      for(p = servinfo; p != NULL; p = p->ai_next) { // P = THE LINKED LIST OF structInfo
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) { // create socket object
          perror("server: socket");
          continue;
        }
        // specify that, once the program finishes, the port can be reused by other processes
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
          perror("setsockopt");
          exit(1);
        }
         int mybind = bind(sockfd, p->ai_addr, p->ai_addrlen);// bind to the specified port number
         
        if (mybind == -1) { 
          close(sockfd);
          perror("server: bind");
          continue;
        }
        goodbind = 0; // if we reach here we have a good bind
        break; // if the code reaches this point, the socket was properly created and bound
      } 
    } 

    struct sockaddr_in mySockAddr;
    socklen_t mySALength = (socklen_t) sizeof(mySockAddr);
    int getSock =getsockname(sockfd, (struct sockaddr*)&mySockAddr, &mySALength);
    if(getSock ==-1){
        perror("getsocket() failed");
    }
    char *localIP= malloc(sizeof(char*)+1);

    if(  (gethostname(localIP,sizeof(localIP) ))==-1) {// stores IP in localIP
        perror( "getHostName() failed");
    }; 

    // get the two port-values to pass to client
     int porta = (int) ntohs(mySockAddr.sin_port);
        int myp1 = porta/ 256;
        int myp2 = porta % 256; 
 
    
    // GETS THE LOCALIP 
    struct hostent* localHost;
    localHost= gethostbyname(localIP);
    free(localIP); // FREE the malloc for IP address. 
    localIP = inet_ntoa (*(struct in_addr *)*localHost->h_addr_list);

   // all done with this structure
   freeaddrinfo(servinfo);
  
  // if p is null, the loop above could create a socket for any given address
  if (p == NULL)  {
    fprintf(stderr, "server: failed to bind\r\n");
    exit(1);
  }
  
  // sets up a queue of incoming connections to be received by the server
  if (listen(sockfd, BACKLOG) == -1) {
    perror("listen");
    exit(1);
  }
  
  // set up a signal handler to kill zombie forked processes when they exit
  sa.sa_handler = sigchld_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    perror("sigaction");
    exit(1);
  }
     // this prints the IP and two-port values to the client to access data connection
      handlepassivemode(fd, localIP, myp1, myp2);
 
  while(1) {
   
    // wait for new client to connect
    sin_size = sizeof(their_addr);
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
  
    
    if (new_fd == -1) {
      perror("accept");
      continue;
    }
   
    inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr),
        s, sizeof(s)); // get the IP address of client!
    
    // Create a new process to handle the new client; parent process
    // will wait for another client.
    if (!fork()) {
      // this is the child processf
      close(sockfd); // child doesn't need the listener
      return new_fd;
      //  close(new_fd);
      //  exit(0);
    }
    
    // Parent proceeds from here. In parent, client socket is not needed.
    close(new_fd);
  }
}


int startsWith(const char *pre, const char *str){ // helper function to check if input begins with certain character
  size_t lenpre = strlen(pre),
  lenstr = strlen(str);
  return lenstr < lenpre ? 0 : strncmp(pre, str, lenpre) == 0;
}


void handle_client(int fd) { //main function that 
  int good;

  char ftp_begin_dir[MAX_LINE_LENGTH + 1] = {0};
  getcwd(ftp_begin_dir,MAX_LINE_LENGTH + 1);
  net_buffer_t recvBuf = nb_create(fd, MAX_LINE_LENGTH);
  char buf[MAX_LINE_LENGTH + 1] = {0};
  send_string(fd, "220 - Service ready for new user\r\n");
  int val = 1;

  // parsing input into separate strings
  while (val == 1) {
    nb_read_line(recvBuf, buf);
    char *token;
    char *myArray[100];
    int i = 0;
    token = strtok(buf, " \t\r\n");

    while (token) {
      myArray[i] = token;
      token = strtok(NULL, " \t\r\n");
      i++;
    }
    char *one = myArray[0];
    char *two = myArray[1];
    char *three = myArray[2];

    if (strcasecmp(one, "USER") == 0 && strcmp(two, "cs317") == 0 && three == NULL) { //login // && (three == NULL || strcmp(&three[0], "/0") == 0)
      login = 1;
      send_string(fd, "230 - User logged in, proceed\r\n");// User logged in, proceed.
    }
    else if (strcasecmp(one, "USER") == 0 && (strcmp(two, "cs317") != 0 || !two || three != NULL )){ // second param is not "cs317" OR isNull OR subcommand number > 2
       send_string(fd, "501 - Syntax error in parameters or arguments\r\n"); //syntax error in parameters or aguments
    }
    else {send_string(fd, "530 - Not logged in\r\n"); // Not logged in.
    }
    while (login == 1) { //while we are logged into the correct user we have access to all implemented commands
      char* loggedArray[100];
      nb_read_line(recvBuf, buf);// read line
      char *token;
      int i = 0;
      token = strtok(buf, " \t\r\n");

      // parsing input into separate strings
      while (token) {
        loggedArray[i] = token;
        token = strtok(NULL, " \t\r\n");
        i++;
      }
      char *command = loggedArray[0]; 
      char *input_string_1 = loggedArray[1];
      char *input_string_2 = loggedArray[2];

      if ((strcasecmp(command, "USER") == 0)) { //allows user to re-login

        if (strcasecmp(one, "USER") == 0 && strcmp(two, "cs317") == 0 && three == NULL) { //login // && (three == NULL || strcmp(&three[0], "/0") == 0)
          login = 1;
          send_string(fd, "230 - User logged in, proceed\r\n");// User logged in, proceed.
        }
        else if (strcasecmp(one, "USER") == 0 && (strcmp(two, "cs317") != 0 || !two || three != NULL )){ // second param is not "cs317" OR isNull OR subcommand number > 2
          send_string(fd, "501 - Syntax error in parameters or arguments\r\n"); //syntax error in parameters or aguments
        }
        else {
          send_string(fd, "530 - Not logged in\r\n"); // Not logged in.
        }

      } else if ((strcasecmp(command, "QUIT") == 0)) { 

        if (input_string_1 == NULL){ // Quit if no subcommands
          val = 0;
          login = 0;
          send_string(fd, "221 - Service closing control connection: Goodbye\r\n"); //Service closing control connection. 
          nb_destroy(recvBuf);
          close(dataSocket);
          return;
        } 
        else if(input_string_1 != NULL){ // Quit if there are subcommands fail
          send_string(fd, "500 - Syntax error, command unrecognized\r\n"); //Syntax error,command
        }

      } else if ((strcasecmp(command, "CWD") == 0)) { 
          
          if (input_string_1 == NULL || input_string_2 != NULL){
            send_string(fd, "501 - Syntax error in parameters or arguments\r\n"); //Syntax error in parameters or arguments.
          }
          else if(startsWith(".", input_string_1) == 1  || strstr(input_string_1, "..") != NULL) { //not accept any CWD command that starts with ./ or ../ or contains ../
            send_string(fd, "550 - Requested action not taken\r\n"); //Requested action not taken. 
          }
          else {
              char cwd[MAX_LINE_LENGTH + 1] = {0};
              memset(cwd,0,MAX_LINE_LENGTH + 1);
              getcwd(cwd,MAX_LINE_LENGTH + 1); //get current directory
              char dest[sizeof(input_string_1)+ 1] = "/";
              strcat(dest, input_string_1);//append slash to input name "/name"
              char final_dest[sizeof(cwd) + sizeof(dest)];
              strncpy(final_dest, cwd,sizeof(cwd)); 
              strcat(final_dest, dest); //append directory path + "/name"
              char old_dir[MAX_LINE_LENGTH + 1];
              strncpy(old_dir, cwd,sizeof(cwd)); 
                    
              chdir(trimwhitespace(final_dest)); //change directory

              getcwd(cwd,MAX_LINE_LENGTH + 1);
              char new_dir[MAX_LINE_LENGTH + 1];
              strncpy(new_dir, cwd,sizeof(cwd)); 

              if (strcmp(old_dir,new_dir) == 0){ //if path doesn't exist or is the same
                send_string(fd, "550 - Requested action not taken\r\n"); //Requested action not taken. 
              }
              else{
                    memset(cwd,0,MAX_LINE_LENGTH + 1);
                    getcwd(cwd,MAX_LINE_LENGTH + 1);
                    char message[MAX_LINE_LENGTH + 1] = "250 - Requested file action okay, completed: your current directory is ";
                    strcat (message, cwd);
                    strcat (message, "\r\n");
                    send_string(fd, message); //Requested file action okay, completed + current directory
                  }
          }

      } else if ((strcasecmp(command, "CDUP") == 0)) { 
               
          if(input_string_1 != NULL){
            send_string(fd, "501 - Syntax error in parameters or arguments\r\n"); //Syntax error in parameters or arguments.

          }else if (input_string_1 == NULL){ 
            char cwd[MAX_LINE_LENGTH + 1] = {0};
            getcwd(cwd,MAX_LINE_LENGTH + 1); // get current directory

            if (strcmp(cwd,ftp_begin_dir) == 0){
              send_string(fd, "550 - Requested action not taken\r\n");
            }
            else{ //if current dir is NOT equals to where the ftp server is started then change dir
              char *last_backslash = strrchr((cwd), '/');//get pointer to last occurrence of  "/"
              int length_curr_dir = strlen((cwd));// length of current directory path
              int length_backlash = strlen(last_backslash); //get length of name of current directory
              int size_substract = length_curr_dir - length_backlash; //size to copy from current path to parent directory       
              char dest[size_substract];
              strncpy(dest,(cwd),size_substract);

              chdir((dest));//change dir to parent
              memset(cwd,0,MAX_LINE_LENGTH + 1);
              getcwd(cwd,MAX_LINE_LENGTH + 1);
              char message [MAX_LINE_LENGTH + 1] = "250 - Requested file action okay, completed: your current directory is ";
              strcat (message, cwd);
              strcat (message, "\r\n");
              send_string(fd, message); //Requested file action okay, completed + current directory
            }  
          }

      } else if ((strcasecmp(command, "TYPE") == 0)) {

          if (input_string_1 == NULL || input_string_2 != NULL){
            send_string(fd,"501 - Syntax error in parameters or arguments\r\n");// Syntax error in parameters or arguments
          }
          else if (strcasecmp(input_string_1, "a") == 0){ //ascii
            type = 0; //set to ascii
            send_string(fd,"200 - Command okay ASCii type\r\n"); // command ok
          }
          else if (strcasecmp(input_string_1, "i") == 0){ //image
            type = 1; //set to image
            send_string(fd,"200 - Command okay Image type\r\n"); // command ok
          }
          else if ((strcasecmp(input_string_1, "e") == 0) || (strcasecmp(input_string_1, "l") == 0)){
            send_string(fd,"504 - Command not implemented for that parameter\r\n"); 
          }
          else {
            send_string(fd,"504 - Command not implemented for that parameter\r\n"); 
          }
                
      } else if ((strcasecmp(command, "MODE") == 0)) {

          if (input_string_1 == NULL || input_string_2 != NULL){
            send_string(fd,"501 - Syntax error in parameters or arguments\r\n");// Syntax error in parameters or arguments
          }
          else if ((strcasecmp(input_string_1, "s") == 0)){ //stream 
            send_string(fd,"200 - Command okay\r\n"); // command ok
          }
          else{
            send_string(fd,"504 - Command not implemented for that parameter\r\n"); 
          }

      } else if ((strcasecmp(command, "STRU") == 0)) {

          if (input_string_1 == NULL || input_string_2 != NULL){
            send_string(fd,"501 - Syntax error in parameters or arguments\r\n");// Syntax error in parameters or arguments
          }
          else if ((strcasecmp(input_string_1, "f") == 0)){ //file structure
            send_string(fd,"200 - Command okay\r\n"); // command ok
          }
          else{
            send_string(fd,"504 - Command not implemented for that parameter\r\n"); 
          }

      } else if ((strcasecmp(command, "RETR") == 0)) {
                
          if (input_string_1 == NULL || input_string_2 != NULL){
            send_string(fd,"501 - Syntax error in parameters or arguments\r\n");// Syntax error in parameters or arguments
          }
          if (dataSocket == -43){
            send_string(fd, "425 - Can't open data connection. Passive mode not started\r\n");

          }else {
             good= handleRETR(input_string_1,fd,dataSocket);
          }
            close(dataSocket);
            dataSocket = -43;

          if( good ==1){
              send_string(fd, "226 - Closing data connection. Requested file action okay,completed\r\n");
          }   
      } else if ((strcasecmp(command, "PASV") == 0)) {

          if (input_string_1 != NULL){
            send_string(fd,"501 - Syntax error in parameters or arguments\r\n");

          }else if (input_string_1 == NULL){
            
            if (dataSocket != -43){ //TODO
              close(dataSocket);
              dataSocket = -43;
            }
        
            dataSocket = handlePASV(fd); 
         
          }
      } else if ((strcasecmp(command, "NLST") == 0)) {  

          if (type == 0){
            if (input_string_1 != NULL){
              send_string(fd,"501 - Syntax error in parameters or arguments\r\n");// Syntax error in parameters or arguments
            }
            if (dataSocket == -43){
              send_string(fd, "425 - Can't open data connection. Passive mode not started.\r\n");
            }
            else{
              send_string(fd,"150 - File status okay; about to open data connection\r\n"); //TODO if I have to print this message? 
              char cwd[260];
              listFiles(dataSocket,getcwd(buf, MAX_LINE_LENGTH + 1));
              send_string(fd,"226 - Closing data connection. Requested file connection okay, completed\r\n");//or is it 226 - Closing data connection. Requested file action sucessful
            }

          }else if (type == 1){
            send_string(fd,"451 - Requested action aborted; local error in processing: type used for command is not correct\r\n");//todo check this 
          }
          close(dataSocket);
          dataSocket = -43;

      } else { 
          send_string(fd, "500 - Syntax error, command unrecognized\r\n"); // Syntax error, command unrecognized OR not implemented
      }
      memset(loggedArray, 0, 99);        
    }
    memset(myArray, 0, 99);
  }
}

