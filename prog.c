// Programul va primi un folder, va parcurge recursiv folderul, poate avea si subfoldere
// Va trebui sa verfice ce s-a schimbat de la prima rulare a programului la a doua in folder orice, o linie de fisier, nume, etc.
//----------------------------------------------------------------------
// ATENTIE: va fi compilat asa: gcc -Wall -o prog prog.c -lssl -lcrypto
//----------------------------------------------------------------------

// Metode de apelare a programului:

//.prog folder1 folder2 folder3...etc (maxim 10 directoare)
//.prog -o outputdir folder1 folder2 folder3...etc (maxim 10  directoare)
//.prog -o outputdir -s izolated_space_dir folder1 folder2 folder3...etc (maxim 10  directoare)
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

#define EXIT -1
#define MAX_FILES 1000
#define BUF_SIZE 4096
#define SHA256_DIG_LENGTH 32
#define FILE_NAME_LENGTH 50

// Structura de date pentru nume si cheksum a unui fisier
typedef struct{
    char numeFisier[PATH_MAX];
    unsigned char hash[SHA256_DIG_LENGTH];
    int isDir;
    mode_t mode;

} SnapshotEntry;

// printeaza stuctura SnapshotEntry
void printSnapshotEntry(SnapshotEntry snapshot){
    printf("Nume fisier: %s\n", snapshot.numeFisier);
    printf("Hash: %s\n", snapshot.hash);
    printf("IsDir: %d\n", snapshot.isDir);
    printf("Mode: %d\n", snapshot.mode);
}

// functia pentru deschidere folder

DIR *deschideFolder(const char *nume){

    DIR *folder;

    if ((folder = opendir(nume)) == NULL){
        perror("EROARE: Deschidere director.\n");
        exit(EXIT);
    }
    return folder;
}

// functia pentru inchidere folder

void inchideFolder(DIR *folder){

    if(closedir(folder) != 0){
        perror("EROARE: Inchidere director.\n");
        exit(EXIT);
    }
    
}

// functie deschidere fisier

int deschideFisier(const char *nume, int flag){

    int fd;

    if((fd = open(nume,flag))== -1){
        perror("EROARE: Deschidere fisier.\n");
        return -2;  //  va trebui sa tratam eroarea de deschidere, nu putem sa inchidem programul
    }

    return fd;
}

// functie inchidere fisier

int inchidereFisier(int fd){

    if(close(fd)== -1){
        perror("EROARE: Inchidere fisier.\n");
        return -2;
    }
    return -1;
}

// functie pentru a calcula suma de control SHA-256 a unui folder

int calculeazaSHA256(const char *numeFisier, unsigned char *hash){

    int fd;
    fd = deschideFisier(numeFisier, O_RDONLY);

    SHA256_CTX context;

    if(!SHA256_Init(&context)){
        perror("EROARE");
        inchidereFisier(fd);
        return 0;
    }

    unsigned char buf[BUF_SIZE];
    ssize_t bytes_read;

    // vom citi in buffer

    while((bytes_read = read(fd, buf, sizeof(buf))) > 0){

        if(!SHA256_Update(&context,buf,bytes_read)){
            perror("EROARE");
            inchidereFisier(fd);
            return 0;
        }
    }

    if(!SHA256_Final(hash, &context)){
        perror("EROARE");
        inchidereFisier(fd);
        return 0;
    }
    
    inchidereFisier(fd);
    return 1;

}

// functie pentru parcurgere a folderul

void parcurgereFolder(DIR *folder, char const *nume, SnapshotEntry *snapshot, int *count){

    // structua pentru a citi un folder

    struct dirent *entry;

    while ((entry = readdir(folder)) != NULL) {

        // ignoram directorul celfisierele care arat catre directorul parinte, cel curent, si cel snapshot

        if(strcmp(entry->d_name,".") == 0 || strcmp(entry->d_name,"..") == 0 || strstr(entry->d_name, "snapshot.dat") != NULL ){
            continue;
        }

        // bagam in variabila cale calea folderul si numele de fisier
        // pentru a construi nua cale relativa

        char cale[PATH_MAX];
        snprintf(cale,sizeof(cale),"%s/%s",nume,entry->d_name);

        //printf("Fisier: %s\n", cale);

        // aflam atributele fisierului, in acest caz ce tip de inregistrare e

        struct stat statbuf;
        if(lstat(cale,&statbuf) == -1){
            fprintf(stderr,"EROARE: la citirea atributelor fisierului %s\n", entry->d_name);
            continue;
        }
        
        // aplicam un macro care ne spune din structura statbuf in variabila st_mode daca e director
        // daca e director se aplica recursiv functia
        // daca nu e, se prelucreaza inregistrarea

        if(S_ISDIR(statbuf.st_mode)){
        
            DIR *subfolder;
            // trebue prelucrat folderul

            //  printf("Director: %s \n", cale);

            snapshot[*count].isDir = 1;
            strcpy(snapshot[*count].numeFisier,cale);
            (*count)++;

            // si calculam suma de control al folderului

            subfolder = deschideFolder(cale);
            parcurgereFolder(subfolder,cale, snapshot, count); // apelam recursiv pentru subdirector
            inchideFolder(subfolder);
        }else{

            // trebue prelucrat fisierul

            snapshot[*count].isDir = 0;
            strcpy(snapshot[*count].numeFisier, cale);
            snapshot[*count].mode = statbuf.st_mode;

            // printSnapshotEntry(snapshot[*count]);

            // verificam daca are persmisiuni de scriere si citire

             if ((snapshot[*count].mode & S_IRUSR) && (snapshot[*count].mode & S_IWUSR)){

                // calculamm suma de control SHA-256 a fisierului care are drepturi de citire si scriere
            
                if(calculeazaSHA256(cale,snapshot[*count].hash) == 0){
                    fprintf(stderr,"Eroare la calularea sumei de control ai fisierului %s.\n", cale);
                    continue;
                }

            }
            (*count)++;
        }
    }
}

// scriere snapshot in fisier

int scrieSnapshot(const char *numeFolder, const char *numeFisier, SnapshotEntry *snapshot, int count) {

    DIR *folder;

    // deschidem folderul

    folder = deschideFolder(numeFolder);

    // bagam in variabila cale calea folderul si numele de fisier
    // pentru a construi nua cale relativa

    char cale[PATH_MAX];
    snprintf(cale,sizeof(cale),"%s/%s",numeFolder,numeFisier);

    // cream sau deschidem fisierul snapshot si suprascriem datele

    int fd = open(cale, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        perror("EROARE: Deschidere fisier snapshot.\n");
        return 0;
    }

    if (write(fd, snapshot, count * sizeof(SnapshotEntry)) == -1) {
        perror("EROARE: Scriere in fisier snapshot fisier snapshot.\n");
        close(fd);
        return 0;
    }

    close(fd);
    inchideFolder(folder);

    return 1;
}

// citire a unui fisier sanpshot

int citesteSnapshot(const char *numeFolder,const char *numeFisier, SnapshotEntry *snapshot, int *count) {

    DIR *folder;

    // deschidem folderul

    folder = deschideFolder(numeFolder);

    // structua pentru a citi un folder

    struct dirent *entry;

    // citim din folder fisierul snapshot

    while ((entry = readdir(folder)) != NULL) {

        if(strcmp(entry->d_name,numeFisier) == 0){

            // bagam in variabila cale calea folderul si numele de fisier
            // pentru a construi nua cale relativa

            char cale[PATH_MAX];
            snprintf(cale,sizeof(cale),"%s/%s",numeFolder,numeFisier);

            int fd = open(cale, O_RDONLY);
            if (fd == -1) {
                perror("EROARE: Deschidere fisier snapshot.\n");
                return 0;
            }

            // obtinem atributele unui fisier

            struct stat statbuf;

            if (fstat(fd, &statbuf) == -1) {
                perror("Eroare: Obtinere atributele fisierului de snapshot");
                close(fd);
                return 0;
            }

            // cu marimea fisierului si a structuri snapshot, stim numarul de chekcsums din fisier

            *count = statbuf.st_size / sizeof(SnapshotEntry);

            // citim din fisierul de snapshot

            if (read(fd, snapshot, statbuf.st_size) == -1) {
                perror("EROARE: Citire din fisierul snapshot");
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

// compararea a doua snapshoturi

// prin conventie, vom face ca snaphsot1 sa fie cel actual, si snapshot2 sa fie cel anterior

void comparaSnapshoturi(SnapshotEntry *snapshot1, int count1, SnapshotEntry *snapshot2, int count2) {

    int modificareFolder = 0;

    // parcurgem primul snapshot(cel actual) pentru ac gasi adaugarile

    for (int i = 0; i < count1; i++) {
        int gasit = 0;
        int subfolderGasit = 0;

     //   printf("Actual: %s, %d\n",snapshot1[i].numeFisier, snapshot1[i].isDir);

        // cautam elementul din primul in al doilea

        for (int j = 0; j < count2; j++) {

        // printf("Vechi:%s\n",snapshot2[j].numeFisier);
    
            // verificam daca este folder si daca exista folderul

            if((snapshot1[i].isDir == 1)){
                if(strcmp(snapshot1[i].numeFisier, snapshot2[j].numeFisier) == 0){
                    subfolderGasit = 1;
                    break;
                }
            }
            else{

                // comparam numele fisererului

                if (strcmp(snapshot1[i].numeFisier, snapshot2[j].numeFisier) == 0) {
                    gasit = 1;
                    if (memcmp(snapshot1[i].hash, snapshot2[j].hash, SHA256_DIGEST_LENGTH) != 0) {
                        modificareFolder=1;
                        printf("Fisierul %s a fost modificat.\n", snapshot1[i].numeFisier);
                    }
                    if (snapshot1[i].isDir != snapshot2[j].isDir) {
                        modificareFolder=1;
                        printf("FIsierul %s a fost modificat: tipul de fisier s-a schimbat.\n", snapshot1[i].numeFisier);
                    }
                    break;
                }  
            }
        }
        if (!gasit && (snapshot1[i].isDir == 0) && ((snapshot1[i].mode & S_IRWXU) || (snapshot1[i].mode & S_IRWXG) || (snapshot1[i].mode & S_IRWXO))) {
            modificareFolder=1;
            printf("Fisierul %s a fost adăugat.\n", snapshot1[i].numeFisier);
        }
        if((snapshot1[i].isDir == 1) && (subfolderGasit == 0)){
            modificareFolder=1;
            printf("Subdirectorul %s a fost adaugat\n",snapshot1[i].numeFisier);
        }
     //   printf("----------\n");
    }

    // Parcurgem al doilea snapshot (cel anterior) pentru a găsi elementele eliminate

    for (int i = 0; i < count2; i++) {
        
        int gasit = 0;
        int subfolderGasit = 0;

        // Căutăm elementul din al doilea snapshot în primul snapshot
        for (int j = 0; j < count1; j++) {
            
             // verificam daca este folder si daca exista  exista folderul

            if((snapshot2[i].isDir == 1)){
                if(strcmp(snapshot2[i].numeFisier, snapshot1[j].numeFisier) == 0){
                    subfolderGasit = 1;
                    break;
                }
            }
            else{
                if (strcmp(snapshot2[i].numeFisier, snapshot1[j].numeFisier) == 0) {
                    gasit = 1;
                    break;     
                }  
            }   
        }

        // Dacă elementul din al doilea snapshot nu a fost găsit în primul snapshot, înseamnă că a fost sters

        if (!gasit && (snapshot2[i].isDir == 0)) {
            modificareFolder = 1;
            printf("Fisierul %s a fost sters.\n", snapshot2[i].numeFisier);
        } 
        if((snapshot2[i].isDir == 1) && (subfolderGasit == 0)){
            modificareFolder=1;
            printf("Subdirectorul %s a fost sters\n",snapshot2[i].numeFisier);
        }
    }

    if (!modificareFolder) {
        printf("Nu există modificări.\n");
    }

}

// functie care analizeaza un folder intreg

// TODO: Va trebui trata erorile pentru, nu poate sa se inchid programul doar pentru o eroare intru folder 
// care a avut vreo eroare, ci va trebue sa sara la celelate foldere pentru analiza

int analizareFolder(const char *nume, const char *output, const char *izolated_space_dir){

     // vom apela functia pentru a deschide folderul dat ca parametru

    DIR *folder;
    folder = deschideFolder(nume);

    // initializam structura snapshot pentru toate fisierele unde vom stoca
    // numele fisierului si checksum

    SnapshotEntry snapshot[MAX_FILES];
    int count = 0;

    // parcurgem folferul si calculam cheksum pentru toate fisierele
    // si le punem in structura snapshot

    parcurgereFolder(folder, nume, snapshot, &count);

    // vom apela functia pentru a inchide folderul

    inchideFolder(folder);

    // verificam daca exista un fisier snapshot in folderul principal
    // daca exista apelam functia de comparare a snapshotului calculat cacum cu cel din fisier
    // daca nu, vom printa ca este nu exista modificari

    SnapshotEntry snapshot_anterior[MAX_FILES];
    int count_anterior = 0;

    // cream numele fisierului de snapshot

    char nume_fis[FILE_NAME_LENGTH];
    snprintf(nume_fis,sizeof(nume_fis),"%s_%s",nume,"snapshot.dat");

    if (citesteSnapshot(nume,nume_fis, snapshot_anterior, &count_anterior)) {
        // Facem comparatia intre snapshotul anterior si cel actual
        comparaSnapshoturi(snapshot, count, snapshot_anterior, count_anterior);
    } else{
        printf("Prima rulare, deci nu exista un snapshot anterior.\n");
    }

    // scriem snapshotul actualizat intr-un fisier in directorul care il analizam sau in
    // directorul output specifica ca argument in linie de comanda

    if(output == NULL){
        if (!scrieSnapshot(nume,nume_fis, snapshot, count)){
            perror("EROARE: Creare fisier snapshot.\n");
            inchideFolder(folder);
            exit(EXIT);
        }
    }else {
        if (!scrieSnapshot(output,nume_fis, snapshot, count)){
            perror("EROARE: Creare fisier snapshot.\n");
            inchideFolder(folder);
            exit(EXIT);
        }
    }

    if(izolated_space_dir != NULL){

        // parcurgem snapshotul si vedem daca sunt fisiere care au toate drepurile lipsa

        int nrFisiereCorupte = 0;    

        for(int i = 0; i < count; i++){
            if(snapshot[i].isDir == 0){
                if((snapshot[i].mode & S_IRWXU) == 0 &&
                    (snapshot[i].mode & S_IRWXG) == 0 &&
                    (snapshot[i].mode & S_IRWXO) == 0){

                    // vom crea un proces copil care va apela un script shell care verifica daca fisierul este malitios

                    // Pentru acea vom crea un pipe pentru a comunica intre procesul parinte si fiu

                    int pipefd[2];

                    if(pipe(pipefd) < 0){
                        perror("EROARE: Creare pipe pentru comunicarea intre porcesul parinte si fiu.\n");
                        exit(EXIT);
                    }

                    int pid = fork();
                    
                    if(pid < 0){
                        perror("EROARE: Creare proces copil pentru directorul scriptul bash.\n");
                        exit(EXIT);
                    }
                    
                    // se va apela exec cu scriptorul verify_for_malicious.sh in procesul fiu

                    if(pid == 0){// procesul fiu
                        
                        close(pipefd[0]);   // inchidem capatul de citire al pipe-ului

                        // reduirectam iesirea standard a erorilor si al outputului in pipe
                        dup2(pipefd[1],1);
                        dup2(pipefd[1],2);

                        close(pipefd[1]);   // inchidem capatul de scriere al pipe-ului

                        execl("/home/mihai/Desktop/SO/lab6/verify_for_malicious.sh", "/home/mihai/Desktop/SO/lab6/verify_for_malicious.sh", snapshot[i].numeFisier, NULL);
                        // daca e eroare la apelare functiei execlp
                        perror("EROARE: la apelul scriptului verify_for_malicious.sh.\n");
                        exit(EXIT);
                    }else{// procesul parinte
                        
                        close(pipefd[1]);  // inchidem capatul de scriere al pipe-ului

                        char buffer[FILE_NAME_LENGTH];

                        // citim din pipe
                        while (read(pipefd[0], buffer, sizeof(buffer)) != 0) {
                            // daca ce am citit este diferit de SAFE, atunci fisierul este malitios
                            if(strcmp(buffer,"SAFE") != 0){
                                printf("Fisierul %s este malitios.\n", snapshot[i].numeFisier);
                                nrFisiereCorupte++;

                                //extragem doar numele a fisierului
                                char* numeFisier = basename(snapshot[i].numeFisier);

                                printf("%s\n", numeFisier);

                                // cream noua cale relativa a fisierului malitios
                                char cale[PATH_MAX];
                                snprintf(cale,sizeof(cale),"%s/%s",izolated_space_dir,numeFisier);

                                if(rename(snapshot[i].numeFisier,cale) != 0){
                                    perror("EROARE: La mutarea fisierului malitios.\n");
                                    exit(EXIT);
                                }   
                                
                            }
                            break;
                        }
                        close(pipefd[0]);  // inchidem capatul de citire al pipe-ului
                    }
                }
            }
        }
        return nrFisiereCorupte;
    }
    return 1;
}

// se da ca parametru in linie de comanda folderele

// pentru a crea procesul parinte si copil, intrebam pe github copilot
// in the actual code, what can i modify to do a father proces that appels
// a some son proces and the son proces ar the folders give at parameters, arg[2], argv[3], etc

int main(int argc, char** argv){

    // declaram variabilele pentru a stoca ID procesului (PID) si status al procesii fii

    int pid;
    int status;

    // declaram variabilele pentru a parcurge argumentele date ca parametru
    
    // pentru verificarea directoarelor
    int i = 1; 
    // pentru crearea proceselor
    int j = 1;
    // daca suntem in functionalitatea -o
    int dirOutput = 0;
    // daca suntem in functionalitatea -s
    int dirMove = 0;
   
    // verificam nr de argumente date ca parametru

    if(argc < 2){
        perror("Eroare: Numar de argumente de linie de comanda gresit.\n");
        exit(EXIT);
    }

    if(argc < 4 && strcmp(argv[1], "-o")==0){
        perror("Eroare: Numar de argumente de linie de comanda gresit.\n");
        exit(EXIT);
    }

    // verificam daca se extinde functionalitatea codului cu intrarea "-o" si cu "-s"
    // el va pune toate fisierele snapshot in folderul dat ca parametru 
    // si va muta in-trun alt folder fisierele malitioase
    if(strcmp(argv[1], "-o")==0 && strcmp(argv[3], "-s")==0){
        // verificam ca numarul de argument dat ca parametru e corect

        if(argc > 14 || argc < 5){
            perror("Eroare: Numar de argumente de linie de comanda gresit.\n");
            exit(EXIT);
        }
        i++;
        j+=2;
        dirOutput = 1;
        dirMove = 1;
        }
        else {
            if(strcmp(argv[1], "-o")==0){
         
            // verificam ca numarul de argument dat ca parametru e corect

            if(argc > 13 || argc < 4){
                perror("Eroare: Numar de argumente de linie de comanda gresit.\n");
                exit(EXIT);
            }
            i++;
            j+=2;
            dirOutput = 1;
        }  
        else // daca nu, rulam programul normal
        {
            // verificam ca numarul de argument dat ca parametru e corect
            if(argc > 11 || argc < 2){
                perror("Eroare: Numar de argumente de linie de comanda gresit.\n");
                exit(EXIT);
            }
        }
    }

    // verificam ca argumetele date ca parametru sunt directoare

    // TODO: mai trebue verificat ca parametri sunt diferiti

    for(; i < argc; i++){
        if(dirMove && i==3){
            continue;
        }
        DIR *dir = opendir(argv[i]);
        if (dir) {
            closedir(dir);
        } else {
            fprintf(stderr,"EROARE: %s nu este un folder sau nu poate fi deschis.\n", argv[i]);
            closedir(dir);
            exit(EXIT);
        }
    }

    // Cream un array pentru a pastra PIDs si exitCodes

    pid_t pids[argc - j];
    int exit_codes[argc - j];
   // int snapshot_codes[argc - j];
    int malitios_codes[argc - j];

    // cream un proces copil pentru fiecare folder dat ca parametru
    
    int count = 0;

    for(;j<argc;j++){

        // daca detectam -s, trecem cu j doua pozitii in fata
        if(strcmp(argv[j], "-s")==0){
            // inca o pozitie ca sa trecem de izolated_space_dir
            j++;
            continue;
        }

        int nrFisiereCorupte = 0;    
        int pipefd[2]; // declaram pipe

        // cream un pipe pentru a ne comunica cu procesul fiu
        if(pipe(pipefd) < 0){
            perror("EROARE: Creare pipe pentru comunicarea intre porcesul parinte si fiu.\n");
            exit(EXIT);
        }

        pid = fork();

        if(pid == -1){
            fprintf(stderr,"EROARE: Creare proces copil pentru directorul %s.\n", argv[j]);
            exit(EXIT);
        }
     
        if(pid == 0){ // blocul va fi executat de procesul copil

            close(pipefd[0]); // inchidem capatul de citire al pipe-ului
            int flag = 0; // pentru a determina daca verificam daca fisierul este malitios

            printf("In folderul %s:\n", argv[j]);
            if(dirOutput && dirMove){
                nrFisiereCorupte = analizareFolder(argv[j],argv[2],argv[4]);
                // scriem numarul de fisiere malitioase in pipe
                printf("%d\n", nrFisiereCorupte);
                flag = 1;
                write(pipefd[1], &flag, sizeof(flag));
                write(pipefd[1], &nrFisiereCorupte, sizeof(nrFisiereCorupte));
                
            }
            else if(dirOutput){
                analizareFolder(argv[j],argv[2],NULL);
            }
            else{
                analizareFolder(argv[j],NULL,NULL);
            }
            printf("-----------------\n");

            close(pipefd[1]); // inchidem capatul de scriere al pipe-ului    

            exit(0);
        }
        else{ // Codul de mai jos va fi executat de procesul parinte
            
            close(pipefd[1]); // inchidem capatul de scriere al pipe-ului

            // punem pid-urile in array
            pids[count] = pid;

            // citim din pipe nr de fisiere malitioase
            int flag;
            read(pipefd[0], &flag, sizeof(flag));

             // punem numarul de fisiere cu potential pericol            
            if(flag == 1){
                read(pipefd[0], &malitios_codes[count], sizeof(malitios_codes[count]));
            }

            close(pipefd[0]); // inchidem capatul de citire al pipe-ului  
        }
        count++;
    }

    // procesul parinte va astepta ca procesele fii sa termine 

    for(int k = 0; k < count; k++){
        waitpid(pids[k],&status,0);
        // vom pune codul de iesire in tablou de exit codes
        exit_codes[k] = WEXITSTATUS(status);
    }

    for (int l = 0; l < count; l++){
        if(exit_codes[l] == 0){
            printf("Snapshot for Directory %d created successfully.\n", l+1);
        }
    }

    for(int i = 0; i < count; i++) {
        if(dirMove){
            printf("Child Process %d terminated with PID %d and whith %d potentially dangerous files.\n", i+1, pids[i], malitios_codes[i]);
        }else{
            printf("Child Process %d terminated with PID %d and exit code %d.\n", i+1, pids[i], exit_codes[i]);
        }
    }

    return 0;
}