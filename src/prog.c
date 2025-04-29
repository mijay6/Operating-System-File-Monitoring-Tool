// Author: Dobra Mihai
// Group: 2.1
//----------------------------------------------------------------------
// WARNING, it will be compiled as: gcc -Wall -o prog prog.c -lssl -lcrypto
//----------------------------------------------------------------------
// This program will analyze a series of folders and, depending on how it is
// invoked, will perform different functionalities in these folders.
//----------------------------------------------------------------------
// ./prog folder1 folder2 folder3...etc (maximum 10 directories)

// One or more folders are given as parameters, and the program will calculate the SHA-256 checksum
// of all files in the folder and subfolders and will store the metadata of each file in the folder
// in a snapshot file. It will compare the previous snapshot with the current one and print the changes.
//---------------------------------------------------------------------- 
// ./prog -o outputdir folder1 folder2 folder3...etc (maximum 10 directories)

// The functionality is extended with a -o parameter followed by a folder where 
// the snapshot files of the folders given as parameters will be placed.
//----------------------------------------------------------------------
// ./prog -o outputdir -s isolated_space_dir folder1 folder2 folder3...etc (maximum 10 directories)

// The functionality is extended with a -s parameter followed by a folder where malicious files will be moved.
//----------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <linux/limits.h>
#include <sys/wait.h>
#include <signal.h>
#include <libgen.h>
#include <time.h>

//----------------------------------------------------------------------
// Definition of some constants
//----------------------------------------------------------------------

#define EXIT -1
#define MAX_FILES 1000
#define BUF_SIZE 4096
#define SHA256_DIG_LENGTH 32
#define FILE_NAME_LENGTH 100
#define NAME_SNAPSHOT "snapshot.dat"

//----------------------------------------------------------------------
// Data structure to store information about a file
//----------------------------------------------------------------------

typedef struct{
    char numeFisier[PATH_MAX];              // file name
    unsigned char hash[SHA256_DIG_LENGTH];  // SHA-256 checksum
    int isDir;                              // whether it is a directory (0||1)                             
    mode_t mode;                            // file permissions
    off_t size;                             // file size
    ino_t inode;                            // inode number
    char data[20];                          // last modification date
} SnapshotEntry;

//----------------------------------------------------------------------
// printSnapshotEntry - function to print the contents of a SnapshotEntry structure
//----------------------------------------------------------------------

void printSnapshotEntry(SnapshotEntry snapshot){
    printf("File name: %s\n", snapshot.numeFisier);
    printf("Hash: %s\n", snapshot.hash);
    printf("IsDir: %d\n", snapshot.isDir);
    printf("Mode: %d\n", snapshot.mode);
    printf("Size: %ld\n", snapshot.size);
    printf("Inode Number: %ld\n", snapshot.inode);
    printf("Last modification: %s\n", snapshot.data);
}

//----------------------------------------------------------------------
// deschideFolder - function to open a folder
//----------------------------------------------------------------------

DIR *deschideFolder(const char *nume){

    DIR *folder = NULL;
    
    if ((folder = opendir(nume)) == NULL){
        perror("ERROR: Opening folder.\n");
        exit(EXIT);
    }
    return folder;
}

//----------------------------------------------------------------------
// inchideFolder - function to close a folder
//----------------------------------------------------------------------

void inchideFolder(DIR *folder){
    if(closedir(folder) != 0){
        perror("ERROR: Closing folder.\n");
        exit(EXIT);
    }
}

//----------------------------------------------------------------------
// deschideFisier - function to open a file
//----------------------------------------------------------------------

int deschideFisier(const char *nume, int flag){

    int fd = -1;

    if((fd = open(nume,flag))== -1){
        perror("ERROR: Opening file.\n");
        return -2;  // we will need to handle the open error, we cannot terminate the program
    }

    return fd;
}

//----------------------------------------------------------------------
// inchidereFisier - function to close a file
//----------------------------------------------------------------------

int inchidereFisier(int fd){
    if(close(fd)== -1){
        perror("ERROR: Closing file.\n");
        return -2;
    }
    return -1;
}

//----------------------------------------------------------------------
// calculeazaSHA256 - function to calculate the SHA-256 checksum of a file
//----------------------------------------------------------------------

int calculeazaSHA256(const char *numeFisier, unsigned char *hash){

    int fd = 0;
    fd = deschideFisier(numeFisier, O_RDONLY);

    SHA256_CTX context = {0};

    // the context is a structure that contains all the information
    // necessary to calculate the checksum

    if(!SHA256_Init(&context)){
        perror("ERROR");
        inchidereFisier(fd);
        return 0;
    }

    unsigned char buf[BUF_SIZE] = {0};
    ssize_t bytes_read = 0;

    // we will read into the buffer
    while((bytes_read = read(fd, buf, sizeof(buf))) > 0){
        // update adds the read information to the context variable
        if(!SHA256_Update(&context,buf,bytes_read)){
            perror("ERROR");
            inchidereFisier(fd);
            return 0;
        }
    }

    // this function will calculate the checksum and place it in the hash variable
    if(!SHA256_Final(hash, &context)){
        perror("ERROR");
        inchidereFisier(fd);
        return 0;
    }
    
    inchidereFisier(fd);
    return 1;
}

//----------------------------------------------------------------------
// scrieSnapshot - function to write the snapshot file of the folder
//----------------------------------------------------------------------

int scrieSnapshot(const char *numeFolder, const char *numeFisier, SnapshotEntry *snapshot, int count) {

    DIR *folder = NULL;
    folder = deschideFolder(numeFolder);

    char cale[PATH_MAX];
    memset(cale, '\0', sizeof(cale));
    snprintf(cale,sizeof(cale),"%s/%s",numeFolder,numeFisier);

    // create or open the snapshot file and overwrite the data

    int fd = open(cale, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        perror("ERROR: Opening snapshot file.\n");
        return 0;
    }

    if (write(fd, snapshot, count * sizeof(SnapshotEntry)) == -1) {
        perror("ERROR: Writing to snapshot file.\n");
        close(fd);
        return 0;
    }

    inchidereFisier(fd);
    inchideFolder(folder);
    return 1;
}

//----------------------------------------------------------------------
// citesteSnapshot - function to read the snapshot file of the folder
//----------------------------------------------------------------------

int citesteSnapshot(const char *numeFolder,const char *numeFisier, SnapshotEntry *snapshot, int *count) {

    DIR *folder = NULL;
    folder = deschideFolder(numeFolder);

    struct dirent *entry = NULL;

    // read the snapshot file from the folder
    while ((entry = readdir(folder)) != NULL) {
        if(strcmp(entry->d_name,numeFisier) == 0){
            // put in the variable path, the folder path and file name
            // to construct a new relative path
            char cale[PATH_MAX];
            memset(cale, '\0', sizeof(cale));
            snprintf(cale,sizeof(cale),"%s/%s",numeFolder,numeFisier);

            int fd = open(cale, O_RDONLY);
            if (fd == -1) {
                perror("ERROR: Opening snapshot file.\n");
                return 0;
            }

            // get the attributes of a file
            struct stat statbuf;

            if (fstat(fd, &statbuf) == -1) {
                perror("ERROR: Getting attributes of snapshot file");
                close(fd);
                return 0;
            }

            // with the file size and the snapshot structure, we know the number of checksums in the file
            *count = statbuf.st_size / sizeof(SnapshotEntry);

            // read from the snapshot file
            if (read(fd, snapshot, statbuf.st_size) == -1) {
                perror("ERROR: Reading from snapshot file");
                close(fd);
                return 0;
            }
            inchidereFisier(fd);
            return 1;
        }
    }
    inchideFolder(folder);
    return 0;
}

//----------------------------------------------------------------------
// comparaSnapshoturi - function to compare two snapshots and display changes
// (snapshot1 should be the current one, and snapshot2 should be the previous one)
//----------------------------------------------------------------------

void comparaSnapshoturi(SnapshotEntry *snapshot1, int count1, SnapshotEntry *snapshot2, int count2) {

    int folderModified = 0;

    // Traverse the first snapshot (the current one) to find additions
    for (int i = 0; i < count1; i++) {
        int found = 0;
        int subfolderFound = 0;

        // Search for the element from the first snapshot in the second one
        for (int j = 0; j < count2; j++) {

            // Check if it is a folder and if the folder exists
            if ((snapshot1[i].isDir == 1)) {
                if (strcmp(snapshot1[i].numeFisier, snapshot2[j].numeFisier) == 0) {
                    subfolderFound = 1;
                    break;
                }
            } else {
                // Compare the inode of the file
                if (snapshot1[i].inode == snapshot2[j].inode) {
                    found = 1;
                    // Check if the file name has changed
                    if (strcmp(snapshot1[i].numeFisier, snapshot2[j].numeFisier) != 0) {
                        folderModified = 1;
                        printf("The file name %s was changed to -> %s.\n", snapshot2[j].numeFisier, snapshot1[i].numeFisier);
                    }
                    // Check if the file type has changed
                    if (snapshot1[i].isDir != snapshot2[j].isDir) {
                        folderModified = 1;
                        printf("The file %s was modified: the file type has changed.\n", snapshot1[i].numeFisier);
                    }
                    // Check if the file permissions have changed
                    if (snapshot1[i].mode != snapshot2[j].mode) {
                        folderModified = 1;
                        printf("The permissions of the file %s have been modified.\n", snapshot1[i].numeFisier);
                    }
                    // Check if the file hash has changed (if content was added or removed)
                    if (memcmp(snapshot1[i].hash, snapshot2[j].hash, SHA256_DIGEST_LENGTH) != 0) {
                        folderModified = 1;
                        printf("The file %s has been modified.\n", snapshot1[i].numeFisier);
                    }
                    // Check if the file size has changed
                    if (snapshot1[i].size != snapshot2[j].size) {
                        folderModified = 1;
                        printf("The size of the file %s has been modified.\n", snapshot1[i].numeFisier);
                    }
                    break;
                }
            }
        }
        // If the file is not found in the snapshot, it means it was added
        if (!found && (snapshot1[i].isDir == 0)) {
            folderModified = 1;
            printf("The file %s was added.\n", snapshot1[i].numeFisier);
        }
        // If the subdirectory is not found in the snapshot, it means it was added
        if ((snapshot1[i].isDir == 1) && (subfolderFound == 0)) {
            folderModified = 1;
            printf("The subdirectory %s was added.\n", snapshot1[i].numeFisier);
        }
    }

    // Traverse the second snapshot (the previous one) to find removed elements
    for (int i = 0; i < count2; i++) {
        int found = 0;
        int subfolderFound = 0;

        // Search for the element from the second snapshot in the first snapshot
        for (int j = 0; j < count1; j++) {
            // Check if it is a folder and if the folder still exists
            if ((snapshot2[i].isDir == 1)) {
                if (strcmp(snapshot2[i].numeFisier, snapshot1[j].numeFisier) == 0) {
                    subfolderFound = 1;
                    break;
                }
            } else {
                // Check if the file still exists
                if (snapshot2[i].inode == snapshot1[j].inode) {
                    found = 1;
                    break;
                }
            }
        }
        // If the file from the second snapshot is not found in the first, it means it was deleted
        if (!found && (snapshot2[i].isDir == 0)) {
            folderModified = 1;
            printf("The file %s was deleted.\n", snapshot2[i].numeFisier);
        }
        // If the subdirectory from the second snapshot is not found in the first, it means it was deleted
        if ((snapshot2[i].isDir == 1) && (subfolderFound == 0)) {
            folderModified = 1;
            printf("The subdirectory %s was deleted.\n", snapshot2[i].numeFisier);
        }
    }

    // If there are no changes, display a message
    if (!folderModified) {
        printf("No changes detected.\n");
    }
}

//----------------------------------------------------------------------
// parcurgereFolder - function to traverse a folder
//----------------------------------------------------------------------

void parcurgereFolder(DIR *folder, char const *nume, SnapshotEntry *snapshot, int *count) {

    // Structure to read a folder
    struct dirent *entry = NULL;

    // Read from the folder as long as there is something to read
    while ((entry = readdir(folder)) != NULL) {

        // Ignore files pointing to the parent directory, the current directory, and the snapshot file
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strstr(entry->d_name, NAME_SNAPSHOT) != NULL) {
            continue;
        }

        // Construct the relative path consisting of the folder name and the file name
        char cale[PATH_MAX];
        memset(cale, '\0', sizeof(cale));
        snprintf(cale, sizeof(cale), "%s/%s", nume, entry->d_name);

        // Get the attributes of the file
        struct stat statbuf = {0};
        if (lstat(cale, &statbuf) == -1) {
            fprintf(stderr, "ERROR: Reading attributes of the file %s\n", entry->d_name);
            continue;
        }

        // Apply a macro that tells us from the statbuf structure and the st_mode variable if it is a directory
        // If it is, the function is applied recursively
        // If it is not, the record is processed

        if (S_ISDIR(statbuf.st_mode)) {
            DIR *subfolder = NULL;

            // Store the folder data in the snapshot structure
            snapshot[*count].isDir = 1;
            strcpy(snapshot[*count].numeFisier, cale);
            (*count)++;

            // Call recursively for the subdirectory
            subfolder = deschideFolder(cale);
            parcurgereFolder(subfolder, cale, snapshot, count);
            inchideFolder(subfolder);
        } else {
            // Save the file data in the snapshot structure

            snapshot[*count].isDir = 0;
            strcpy(snapshot[*count].numeFisier, cale);
            snapshot[*count].mode = statbuf.st_mode;
            snapshot[*count].size = statbuf.st_size;
            snapshot[*count].inode = statbuf.st_ino;

            char data_modificare[20];
            memset(data_modificare, '\0', sizeof(data_modificare));
            strftime(data_modificare, 20, "%Y-%m-%d %H:%M:%S", localtime(&statbuf.st_mtime));
            strcpy(snapshot[*count].data, data_modificare);

            // Check if it has read permissions
            if ((snapshot[*count].mode & S_IRUSR)) {
                // Call the function to calculate the SHA-256 checksum of the file
                if (calculeazaSHA256(cale, snapshot[*count].hash) == 0) {
                    fprintf(stderr, "Error calculating the checksum of the file %s.\n", cale);
                    continue;
                }
            }
            (*count)++;
        }
    }
}

//----------------------------------------------------------------------
// analizareFolder - function to analyze a folder and return the number of malicious files
//----------------------------------------------------------------------

int analizareFolder(char *nume, char *output, char *isolated_space_dir) {

    DIR *folder = NULL;
    folder = deschideFolder(nume);

    // Initialize the snapshot structure for all files where file information will be stored
    SnapshotEntry snapshot[MAX_FILES] = {0};
    int count = 0;

    // Call the parcurgereFolder function, which traverses the folder,
    // calculates the checksum, and saves the file information in the snapshot structure
    parcurgereFolder(folder, nume, snapshot, &count);

    inchideFolder(folder);

    // Check if a snapshot file exists in the main folder
    // If it exists, call the function to compare the newly calculated snapshot with the one in the file
    // If it does not exist, display that this is the first run of the program

    SnapshotEntry snapshot_anterior[MAX_FILES] = {0};
    int count_anterior = 0;

    // Create the name of the snapshot file
    char nume_fis[FILE_NAME_LENGTH];
    memset(nume_fis, '\0', sizeof(nume_fis));
    snprintf(nume_fis, sizeof(nume_fis), "%s_%s", nume, NAME_SNAPSHOT);

    if (citesteSnapshot(nume, nume_fis, snapshot_anterior, &count_anterior)) {
        // Compare the previous snapshot with the current one
        comparaSnapshoturi(snapshot, count, snapshot_anterior, count_anterior);
    } else {
        printf("First run, so no previous snapshot exists.\n");
    }

    // Write the updated snapshot to a file in the analyzed directory or in the
    // output directory specified as a command-line argument
    if (output == NULL) {
        if (!scrieSnapshot(nume, nume_fis, snapshot, count)) {
            perror("ERROR: Creating snapshot file.\n");
            exit(EXIT);
        }
    } else {
        if (!scrieSnapshot(output, nume_fis, snapshot, count)) {
            perror("ERROR: Creating snapshot file.\n");
            exit(EXIT);
        }
    }

    // If the name of the folder for isolating malicious files is provided
    if (isolated_space_dir != NULL) {
        int nrFisiereCorupte = 0;

        // Traverse the snapshot and check if there are files with all permissions missing
        for (int i = 0; i < count; i++) {
            if (snapshot[i].isDir == 0) {
                if ((snapshot[i].mode & S_IRWXU) == 0 &&
                    (snapshot[i].mode & S_IRWXG) == 0 &&
                    (snapshot[i].mode & S_IRWXO) == 0) {

                    // Create a child process to call a shell script that checks if the file is malicious
                    // For this, create a pipe to communicate the result between the parent and child process

                    int pipefd[2];
                    if (pipe(pipefd) < 0) {
                        perror("ERROR: Creating pipe for communication between parent and child process.\n");
                        exit(EXIT);
                    }

                    int pid = fork();
                    if (pid < 0) {
                        perror("ERROR: Creating child process for the bash script.\n");
                        exit(EXIT);
                    }

                    if (pid == 0) { // Child process

                        close(pipefd[0]); // Close the read end of the pipe

                        // Redirect standard output and error to the pipe
                        dup2(pipefd[1], 1);
                        dup2(pipefd[1], 2);

                        close(pipefd[1]); // Close the write end of the pipe

                        execl("/home/mihai/Desktop/SO/lab6/verify_for_malicious.sh",
                              "/home/mihai/Desktop/SO/lab6/verify_for_malicious.sh",
                              snapshot[i].numeFisier, NULL);
                        // If there is an error calling the execl function
                        perror("ERROR: Calling the verify_for_malicious.sh script.\n");
                        exit(EXIT);
                    } else { // Parent process

                        close(pipefd[1]); // Close the write end of the pipe

                        char buffer[FILE_NAME_LENGTH];
                        memset(buffer, '\0', sizeof(buffer));
                        // Read from the pipe
                        while (read(pipefd[0], buffer, sizeof(buffer)) != 0) {

                            buffer[strcspn(buffer, "\n")] = 0; // Remove the newline printed by echo in the script

                            if (strcmp(buffer, "SAFE") != 0) { // Check if the read value is different from "SAFE"
                                printf("The file %s is malicious.\n", snapshot[i].numeFisier);
                                nrFisiereCorupte++;

                                // Extract only the file name
                                char *numeFisier = basename(snapshot[i].numeFisier);
                                // Create the new relative path of the malicious file
                                char cale[PATH_MAX];
                                memset(cale, '\0', sizeof(cale));
                                snprintf(cale, sizeof(cale), "%s/%s", isolated_space_dir, numeFisier);

                                if (rename(snapshot[i].numeFisier, cale) != 0) {
                                    perror("ERROR: Moving the malicious file.\n");
                                    exit(EXIT);
                                }
                                break;
                            }
                        }
                        close(pipefd[0]); // Close the read end of the pipe
                    }
                }
            }
        }
        return nrFisiereCorupte;
    }
    return 1;
}

//----------------------------------------------------------------------
// main - the main function
//----------------------------------------------------------------------

int main(int argc, char **argv) {

    // Declare variables to store the process ID (PID) and the status of child processes
    int pid = 0;
    int status = 0;

    // Declare variables to traverse the arguments given as parameters
    int i = 1;            // For verifying directories
    int j = 1;            // For creating processes
    int dirOutput = 0;    // If we are in the -o functionality
    int dirMove = 0;      // If we are in the -s functionality

    // Check the number of arguments given as parameters
    if (argc < 2) {
        perror("Error: Incorrect number of command-line arguments.\n");
        exit(EXIT);
    }
    // Check the number of arguments for extending functionality with -o
    if (argc < 4 && strcmp(argv[1], "-o") == 0) {
        perror("Error: Incorrect number of command-line arguments.\n");
        exit(EXIT);
    }

    // Check if the functionality of the code is extended with "-o" and "-s"
    if (strcmp(argv[1], "-o") == 0 && strcmp(argv[3], "-s") == 0) {
        // Check that the number of arguments given as parameters is correct
        if (argc > 14 || argc < 5) {
            perror("Error: Incorrect number of command-line arguments.\n");
            exit(EXIT);
        }
        i++;
        j += 2;
        dirOutput = 1;
        dirMove = 1;
    } else {
        if (strcmp(argv[1], "-o") == 0) {
            // Check that the number of arguments given as parameters is correct
            if (argc > 13 || argc < 4) {
                perror("Error: Incorrect number of command-line arguments.\n");
                exit(EXIT);
            }
            i++;
            j += 2;
            dirOutput = 1;
        } else { // If not, run the program normally
            if (argc > 11 || argc < 2) {
                perror("Error: Incorrect number of command-line arguments.\n");
                exit(EXIT);
            }
        }
    }

    // Verify that the parameters given are different
    for (int x = 0; x < argc; x++) {
        for (int y = x + 1; y < argc; y++) {
            if (strcmp(argv[x], argv[y]) == 0) {
                fprintf(stderr, "Error: Duplicate argument %s in the command line.\n", argv[x]);
                exit(EXIT);
            }
        }
    }

    // Verify that the arguments given are directories
    for (; i < argc; i++) {
        if (dirMove && i == 3) {
            continue;
        }
        DIR *dir = opendir(argv[i]);
        if (dir) {
            closedir(dir);
        } else {
            fprintf(stderr, "ERROR: %s is not a folder or cannot be opened.\n", argv[i]);
            exit(EXIT);
        }
    }

    // Create an array to store PIDs, exit codes, and the number of malicious files
    pid_t pids[argc - j];
    int exit_codes[argc - j];
    int malitios_codes[argc - j];

    memset(pids, 0, sizeof(pid_t) * (argc - j));
    memset(exit_codes, 0, sizeof(int) * (argc - j));
    memset(malitios_codes, 0, sizeof(int) * (argc - j));

    // Create a child process for each folder given as a parameter
    int count = 0;
    for (; j < argc; j++) {

        // If -s is detected, skip two positions in j
        if (strcmp(argv[j], "-s") == 0) {
            // Skip one more position to move past isolated_space_dir
            j++;
            continue;
        }

        int nrFisiereCorupte = 0;   // Variable for the number of corrupted files
        int pipefd[2];              // Declare pipe

        // Create a pipe to communicate with the child process
        if (pipe(pipefd) < 0) {
            perror("ERROR: Creating pipe for communication between parent and child process.\n");
            exit(EXIT);
        }

        pid = fork();
        if (pid == -1) {
            fprintf(stderr, "ERROR: Creating child process for directory %s.\n", argv[j]);
            exit(EXIT);
        }
     
        if (pid == 0) { // Child process

            close(pipefd[0]); // Close the read end of the pipe
            int flag = 0;     // To determine if the file is malicious

            printf("In folder %s:\n", argv[j]);

            // If running with -o and -s functionality
            if (dirOutput && dirMove) {
                nrFisiereCorupte = analizareFolder(argv[j], argv[2], argv[4]);
                flag = 1;
                write(pipefd[1], &flag, sizeof(flag));
                write(pipefd[1], &nrFisiereCorupte, sizeof(nrFisiereCorupte)); // Write the number of malicious files to the pipe
            }
            // If running with -o functionality
            else if (dirOutput) {
                nrFisiereCorupte = analizareFolder(argv[j], argv[2], NULL);
            }
            // If running normally
            else {
                nrFisiereCorupte = analizareFolder(argv[j], NULL, NULL);
            }
            
            printf("-----------------\n");
            close(pipefd[1]); // Close the write end of the pipe    
            exit(0);
        } else { // Parent process

            close(pipefd[1]); // Close the write end of the pipe

            pids[count] = pid; // Store PIDs in the array

            int flag = 0;
            read(pipefd[0], &flag, sizeof(flag));  // Read from the pipe the number of malicious files

            // Read from the pipe the number of potentially dangerous files
            if (flag == 1) {
                read(pipefd[0], &malitios_codes[count], sizeof(malitios_codes[count]));
            }

            close(pipefd[0]); // Close the read end of the pipe  
        }
        count++;
    }

    // The parent process will wait for the child processes to finish

    for (int k = 0; k < count; k++) {
        waitpid(pids[k], &status, 0);
        exit_codes[k] = WEXITSTATUS(status); // Store the exit code in the exit codes array
    }

    // Print if the snapshot was successfully created
    for (int l = 0; l < count; l++) {
        if (exit_codes[l] == 0) {
            printf("Snapshot for Directory %d created successfully.\n", l + 1);
        }
    }

    // Print the results for each child process
    for (int i = 0; i < count; i++) {
        if (dirMove) {
            printf("Child Process %d terminated with PID %d and with %d potentially dangerous files.\n", i + 1, pids[i], malitios_codes[i]);
        } else {
            printf("Child Process %d terminated with PID %d and exit code %d.\n", i + 1, pids[i], exit_codes[i]);
        }
    }
    return 0;
}