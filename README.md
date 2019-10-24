# FTPServer
Program that provides FTP TCP server functionality through the command-line interface implemented in C. Project developed 
for computer science course.

After compiling in the command-line please run: ./CSftp (port # to connect from) for example:

```./CSftp 9999```

The server accepts commands from the client like:

Username: ```USER cs317```

Change working directory: ```CWD (directory name)```

Change to parent directory: ```CDUP```

Name list of current working directory: ```NLST```

Quit conection: ```QUIT```

File transfer type: ```TYPE (a or i)``` - ascii or binary type only

Transmission mode: ```MODE (s)``` - stream mode only

File structure: ```STRU (f)``` - file structure only

Retrieve file: ```RETR (file name)```

Passive mode: ```PASV```


