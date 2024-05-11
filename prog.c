// Autor: Dobra Mihai
// Grupa: 2.1
//----------------------------------------------------------------------
// ATENTIE, va fi compilat asa: gcc -Wall -o prog prog.c -lssl -lcrypto
//----------------------------------------------------------------------
// Acest program va analiza o serie de foldere si in functie de cum se apeleaza programul,
// va realiza diferite functionalitati in aceste foldere.
//----------------------------------------------------------------------
//./prog folder1 folder2 folder3...etc (maxim 10 directoare)

// Se da ca parametru unul sau mai multe foldere si programul va calcula suma de control SHA-256
// a tuturor fisierelor din folder si subfoldere si va pastra metadatele fiecarei fisiere din folder
// intrun fisier snapshot. Va compara snapshotul anterior cu cel actual si va printa modificarile.
//---------------------------------------------------------------------- 
//./prog -o outputdir folder1 folder2 folder3...etc (maxim 10 directoare)

// Functionalitatea este extinsa cu un parametru -o urmat de un folder unde 
// se vor pune fisierele snapshot ale folderelor date ca parametru
//----------------------------------------------------------------------
//./prog -o outputdir -s izolated_space_dir folder1 folder2 folder3...etc (maxim 10  directoare)

// Functionalitatea este extinsa cu un parametru -s urmat de un folder unde se vor muta fisierele malitioase
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
// Definirea unor constante
//----------------------------------------------------------------------

#define EXIT -1
#define MAX_FILES 1000
#define BUF_SIZE 4096
#define SHA256_DIG_LENGTH 32
#define FILE_NAME_LENGTH 100
#define NAME_SNAPSHOT "snapshot.dat"

//----------------------------------------------------------------------
// Structura de date pentru a stoca informatii despre un fisier
//----------------------------------------------------------------------

typedef struct{
    char numeFisier[PATH_MAX];              // numele fisierului
    unsigned char hash[SHA256_DIG_LENGTH];  // suma de control SHA-256
    int isDir;                              // daca este director (0||1)                             
    mode_t mode;                            // drepturile fisierului
    off_t size;                             // marimea fisierului
    ino_t inode;                            // numarul i-nodului
    char data[20];                          // data ultimei modificari
} SnapshotEntry;

//----------------------------------------------------------------------
// printSnapshotEntry - functie pentru a printa continutul unei structuri SnapshotEntry
//----------------------------------------------------------------------

void printSnapshotEntry(SnapshotEntry snapshot){
    printf("Nume fisier: %s\n", snapshot.numeFisier);
    printf("Hash: %s\n", snapshot.hash);
    printf("IsDir: %d\n", snapshot.isDir);
    printf("Mode: %d\n", snapshot.mode);
    printf("Dimensiune: %ld\n", snapshot.size);
    printf("Numar Inode: %ld\n", snapshot.inode);
    printf("Ultima modificare: %s\n", snapshot.data);
}

//----------------------------------------------------------------------
// deschideFolder - functie pentru a deschide un folder
//----------------------------------------------------------------------

DIR *deschideFolder(const char *nume){

    DIR *folder = NULL;
    
    if ((folder = opendir(nume)) == NULL){
        perror("EROARE: Deschidere folder.\n");
        exit(EXIT);
    }
    return folder;
}

//----------------------------------------------------------------------
// functia inchideFolder - functie pentru a inchide un folder
//----------------------------------------------------------------------

void inchideFolder(DIR *folder){
    if(closedir(folder) != 0){
        perror("EROARE: Inchidere folder.\n");
        exit(EXIT);
    }
}

//----------------------------------------------------------------------
// functia deschideFisier - functie pentru a deschide un fisier
//----------------------------------------------------------------------

int deschideFisier(const char *nume, int flag){

    int fd = -1;

    if((fd = open(nume,flag))== -1){
        perror("EROARE: Deschidere fisier.\n");
        return -2;  //  va trebui sa tratam eroarea de deschidere, nu putem sa inchidem programul
    }

    return fd;
}

//----------------------------------------------------------------------
// functie inchidereFisier - functie pentru a inchide un fisier
//----------------------------------------------------------------------

int inchidereFisier(int fd){
    if(close(fd)== -1){
        perror("EROARE: Inchidere fisier.\n");
        return -2;
    }
    return -1;
}

//----------------------------------------------------------------------
// calculeazaSHA256 - functie pentru a calcula suma de control SHA-256 a unui fisier
//----------------------------------------------------------------------

int calculeazaSHA256(const char *numeFisier, unsigned char *hash){

    int fd = 0;
    fd = deschideFisier(numeFisier, O_RDONLY);

    SHA256_CTX context = {0};

    // contextul este o structura care contine toate informatiile
    // necesare pentru a calcula suma de control

    if(!SHA256_Init(&context)){
        perror("EROARE");
        inchidereFisier(fd);
        return 0;
    }

    unsigned char buf[BUF_SIZE] = {0};
    ssize_t bytes_read = 0;

    // vom citi in buffer
    while((bytes_read = read(fd, buf, sizeof(buf))) > 0){
        // update adauga la variabila context informatia citita
        if(!SHA256_Update(&context,buf,bytes_read)){
            perror("EROARE");
            inchidereFisier(fd);
            return 0;
        }
    }

    // aceasta functie va calcula suma de control si o va pune in variabila hash
    if(!SHA256_Final(hash, &context)){
        perror("EROARE");
        inchidereFisier(fd);
        return 0;
    }
    
    inchidereFisier(fd);
    return 1;
}

//----------------------------------------------------------------------
// scrieSnapshot - functie pentru a scrie fisierul snapshot al folderului
//----------------------------------------------------------------------

int scrieSnapshot(const char *numeFolder, const char *numeFisier, SnapshotEntry *snapshot, int count) {

    DIR *folder = NULL;
    folder = deschideFolder(numeFolder);

    char cale[PATH_MAX];
    memset(cale, '\0', sizeof(cale));
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

    inchidereFisier(fd);
    inchideFolder(folder);
    return 1;
}

//----------------------------------------------------------------------
// citesteSnapshot - functie pentru a citi fisierul snapshot al folderului
//----------------------------------------------------------------------

int citesteSnapshot(const char *numeFolder,const char *numeFisier, SnapshotEntry *snapshot, int *count) {

    DIR *folder = NULL;
    folder = deschideFolder(numeFolder);

    struct dirent *entry = NULL;

    // citim din folder fisierul snapshot
    while ((entry = readdir(folder)) != NULL) {
        if(strcmp(entry->d_name,numeFisier) == 0){
            // bagam in variabila cale, calea folderul si numele de fisier
            // pentru a construi nua cale relativa
            char cale[PATH_MAX];
            memset(cale, '\0', sizeof(cale));
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

//----------------------------------------------------------------------
// comapraSnapshotrui - functia compara cele doua snapshoturi si afiseaza modificarile
// (snaphsot1 sa fie cel actual, si snapshot2 sa fie cel anterior)
//----------------------------------------------------------------------

void comparaSnapshoturi(SnapshotEntry *snapshot1, int count1, SnapshotEntry *snapshot2, int count2) {

    int modificareFolder = 0;

    // parcurgem primul snapshot(cel actual) pentru ac gasi adaugarile
    for (int i = 0; i < count1; i++) {
        int gasit = 0;
        int subfolderGasit = 0;

        // cautam elementul din primul in al doilea
        for (int j = 0; j < count2; j++) {

            // verificam daca este folder si daca exista folderul
            if((snapshot1[i].isDir == 1)){
                if(strcmp(snapshot1[i].numeFisier, snapshot2[j].numeFisier) == 0){
                    subfolderGasit = 1;
                    break;
                }
            }
            else{
                // comparam i-node fisererului
                if(snapshot1[i].inode == snapshot2[j].inode){
                    gasit = 1;
                    // verificam schimbarea numele fisierului
                    if (strcmp(snapshot1[i].numeFisier, snapshot2[j].numeFisier) != 0) {
                        modificareFolder=1;
                        printf("Numele fisierului %s a fos modificat la -> %s.\n",snapshot2[j].numeFisier, snapshot1[i].numeFisier);
                    }
                    // verificam daca sa schimbat tipul de fisier
                    if (snapshot1[i].isDir != snapshot2[j].isDir) {  // daca se shimba tipul de fisier
                        modificareFolder=1;
                        printf("Fisierul %s a fost modificat: tipul de fisier s-a schimbat.\n", snapshot1[i].numeFisier);
                    }
                    // verificam daca sa schimbat drepturile fisierului
                    if (snapshot1[i].mode != snapshot2[j].mode){
                        modificareFolder=1;
                        printf("Drepturile fisierului %s au fost modificate.\n", snapshot1[i].numeFisier);
                    }
                    // verificam daca sa schimbat hash-ul fidierului (daca sa adaugat sters din el)
                    if (memcmp(snapshot1[i].hash, snapshot2[j].hash, SHA256_DIGEST_LENGTH) != 0) {
                        modificareFolder=1;
                        printf("Fisierul %s a fost modificat.\n", snapshot1[i].numeFisier);
                    }
                    // verificam daca sa schimbat marimea fisierului
                    if (snapshot1[i].size != snapshot2[j].size){
                        modificareFolder=1;
                        printf("Marimea fisierului %s a fost modificata.\n", snapshot1[i].numeFisier);
                    }
                    break;
                }  
            }
        }
        // daca nu am gasit fisierul in snapshot inseamna ca a fost adaugat
        if (!gasit && (snapshot1[i].isDir == 0)) {
            modificareFolder=1;
            printf("Fisierul %s a fost adăugat.\n", snapshot1[i].numeFisier);
        }// daca nu am gasit subdirectorul in snapshot inseamna ca a fost adaugat
        if((snapshot1[i].isDir == 1) && (subfolderGasit == 0)){
            modificareFolder=1;
            printf("Subdirectorul %s a fost adaugat\n",snapshot1[i].numeFisier);
        }
    }
    // Parcurgem al doilea snapshot (cel anterior) pentru a găsi elementele eliminate
    for (int i = 0; i < count2; i++) {
        int gasit = 0;
        int subfolderGasit = 0;

        // Căutăm elementul din al doilea snapshot în primul snapshot
        for (int j = 0; j < count1; j++) {
             // verificam daca este folder si daca mai exista folderul
            if((snapshot2[i].isDir == 1)){
                if(strcmp(snapshot2[i].numeFisier, snapshot1[j].numeFisier) == 0){
                    subfolderGasit = 1;
                    break;
                }
            }
            else{
                // verificam daca mai exista fisierul
                if (snapshot2[i].inode ==snapshot1[j].inode) {
                    gasit = 1;
                    break;     
                }  
            }   
        }
        // Daca fisierul din al doilea snapshot nu a fost gasit în primul, inseamna ca a fost sters
        if (!gasit && (snapshot2[i].isDir == 0)) {
            modificareFolder = 1;
            printf("Fisierul %s a fost sters.\n", snapshot2[i].numeFisier);
        } // Daca subdirectorul din al doilea snapshot nu a fost gasit in primul, inseamna ca a fost sters
        if((snapshot2[i].isDir == 1) && (subfolderGasit == 0)){
            modificareFolder=1;
            printf("Subdirectorul %s a fost sters\n",snapshot2[i].numeFisier);
        }
    }
    // Daca nu sant modificari, afisam un mesaj
    if (!modificareFolder) {
        printf("Nu există modificări.\n");
    }
}

//----------------------------------------------------------------------
// parcurgereFolder - functie pentru a parcurge un folder
//----------------------------------------------------------------------

void parcurgereFolder(DIR *folder, char const *nume, SnapshotEntry *snapshot, int *count){

    // structua pentru a citi un folder
    struct dirent *entry = NULL;

    // citim din folder atat timp cat avem ce citit
    while ((entry = readdir(folder)) != NULL) {

        // ignoram fisierele care arat catre directorul parinte, cel curent, si cel snapshot
        if(strcmp(entry->d_name,".") == 0 || strcmp(entry->d_name,"..") == 0 || strstr(entry->d_name, NAME_SNAPSHOT) != NULL ){
            continue;
        }

        // construim calea relativa formata din numele folderului si numele fisierului    
        char cale[PATH_MAX];
        memset(cale, '\0', sizeof(cale));
        snprintf(cale,sizeof(cale),"%s/%s",nume,entry->d_name);

        // aflam atributele fisierului
        struct stat statbuf = {0};
        if(lstat(cale,&statbuf) == -1){
            fprintf(stderr,"EROARE: la citirea atributelor fisierului %s\n", entry->d_name);
            continue;
        }
        
        // aplicam un macro care ne spune din structura statbuf si variabila st_mode, daca e director
        // daca este, se aplica recursiv functia
        // daca nu e, se prelucreaza inregistrarea

        if(S_ISDIR(statbuf.st_mode)){
            DIR *subfolder = NULL;

            // stocam datele folderului in structura snapshot
            snapshot[*count].isDir = 1;
            strcpy(snapshot[*count].numeFisier,cale);
            (*count)++;

            // apelam recursiv pentru subdirector
            subfolder = deschideFolder(cale);
            parcurgereFolder(subfolder,cale, snapshot, count);
            inchideFolder(subfolder);
        }else{
            // salvam date a fisierului in structura snapshot

            snapshot[*count].isDir = 0;
            strcpy(snapshot[*count].numeFisier, cale);
            snapshot[*count].mode = statbuf.st_mode;
            snapshot[*count].size = statbuf.st_size;
            snapshot[*count].inode = statbuf.st_ino;

            char data_modificare[20];
            memset(data_modificare, '\0', sizeof(data_modificare));
            strftime(data_modificare, 20, "%Y-%m-%d %H:%M:%S", localtime(&statbuf.st_mtime));
            strcpy(snapshot[*count].data, data_modificare);

            // verificam daca are persmisiuni de citire
            if ((snapshot[*count].mode & S_IRUSR)){
                // apelam functia calculamm suma de control SHA-256 a fisierului
                if(calculeazaSHA256(cale,snapshot[*count].hash) == 0){
                    fprintf(stderr,"Eroare la calularea sumei de control ai fisierului %s.\n", cale);
                    continue;
                }
            }
            (*count)++;
        }
    }
}

//----------------------------------------------------------------------
// analizareFolder - functie pentru a analiza un folder si returneaza numarul de fisiere malitioase
//----------------------------------------------------------------------

int analizareFolder(char *nume, char *output, char *izolated_space_dir){

    DIR *folder = NULL;
    folder = deschideFolder(nume);

    // initializam structura snapshot pentru toate fisierele unde vom stoce informatiile fisierelor
    SnapshotEntry snapshot[MAX_FILES] = {0};
    int count = 0;

    // apelam functia parcurgereFolder care parcurge folderul si 
    // calculeaza checksum si salveaza informatiile fisierelor din folder in structura snapshot
    parcurgereFolder(folder, nume, snapshot, &count);

    inchideFolder(folder);

    // verificam daca exista un fisier snapshot in folderul principal
    // daca exista, apelam functia de comparare a noul snapshot calculat cu cel din fisier
    // daca nu exista, afisam ca e prima rulare a programului.

    SnapshotEntry snapshot_anterior[MAX_FILES] = {0};
    int count_anterior = 0;

    // cream numele fisierului de snapshot
    char nume_fis[FILE_NAME_LENGTH];
    memset(nume_fis, '\0', sizeof(nume_fis));
    snprintf(nume_fis,sizeof(nume_fis),"%s_%s",nume,NAME_SNAPSHOT);

    if (citesteSnapshot(nume,nume_fis, snapshot_anterior, &count_anterior)) {
        // Facem comparatia intre snapshotul anterior si cel actual
        comparaSnapshoturi(snapshot, count, snapshot_anterior, count_anterior);
    } else{
        printf("Prima rulare, deci nu exista un snapshot anterior.\n");
    }

    // scriem snapshotul actualizat intr-un fisier in directorul care il analizam sau in
    // directorul output specifica ca argument in linie de comanda
    if(output == NULL){
        if (!scrieSnapshot(nume, nume_fis, snapshot, count)){
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
    // daca avem numele folderul pentru izolarea a fisierelor malitioase
    if(izolated_space_dir != NULL){
        int nrFisiereCorupte = 0;

        // parcurgem snapshotul si vedem daca sunt fisiere care au toate drepurile lipsa
        for(int i = 0; i < count; i++){
            if(snapshot[i].isDir == 0){
                if((snapshot[i].mode & S_IRWXU) == 0 &&
                    (snapshot[i].mode & S_IRWXG) == 0 &&
                    (snapshot[i].mode & S_IRWXO) == 0){

                    // vom crea un proces copil care va apela un script shell si care verifica daca fisierul este malitios
                    // pentru acea vom crea un pipe pentru a comunica rezultatul intre procesul parinte si fiu

                    int pipefd[2];
                    if(pipe(pipefd) < 0){
                        perror("EROARE: Creare pipe pentru comunicarea intre procesul parinte si fiu.\n");
                        exit(EXIT);
                    }

                    int pid = fork();
                    if(pid < 0){
                        perror("EROARE: Creare proces copil pentru directorul scriptul bash.\n");
                        exit(EXIT);
                    }
                
                    if(pid == 0){           // procesul fiu
                        
                        close(pipefd[0]);   // inchidem capatul de citire al pipe-ului
                   
                        // reduirectam iesirea standard a erorilor si al outputului in pipe
                        dup2(pipefd[1],1);
                        dup2(pipefd[1],2);

                        close(pipefd[1]);   // inchidem capatul de scriere al pipe-ului

                        execl("/home/mihai/Desktop/SO/lab6/verify_for_malicious.sh", "/home/mihai/Desktop/SO/lab6/verify_for_malicious.sh", snapshot[i].numeFisier, NULL);
                        // daca e eroare la apelare functiei execlp
                        perror("EROARE: la apelul scriptului verify_for_malicious.sh.\n");
                        exit(EXIT);
                    }else{                  // procesul parinte
                        
                        close(pipefd[1]);   // inchidem capatul de scriere al pipe-ului

                        char buffer[FILE_NAME_LENGTH];
                        memset(buffer, '\0', sizeof(buffer));
                        // citim din pipe
                        while (read(pipefd[0], buffer, sizeof(buffer)) != 0) {

                            buffer[strcspn(buffer, "\n")] = 0; // eliminam newline-ul care ne printeaza echo din script

                            if(strcmp(buffer,"SAFE") != 0){ // Verificam daca citim diferit de "SAFE"
                                printf("Fisierul %s este malitios.\n", snapshot[i].numeFisier);
                                nrFisiereCorupte++;

                                //extragem doar numele fisierului
                                char* numeFisier = basename(snapshot[i].numeFisier);
                                // cream noua cale relativa a fisierului malitios
                                char cale[PATH_MAX];
                                memset(cale, '\0', sizeof(cale));
                                snprintf(cale,sizeof(cale),"%s/%s",izolated_space_dir,numeFisier);

                                if(rename(snapshot[i].numeFisier,cale) != 0){
                                    perror("EROARE: La mutarea fisierului malitios.\n");
                                    exit(EXIT);
                                }   
                                break;
                            }
                        }
                        close(pipefd[0]);       // inchidem capatul de citire al pipe-ului
                    }
                }
            }
        }
        return nrFisiereCorupte;
    }
    return 1;
}

//----------------------------------------------------------------------
// main - functia principala
//----------------------------------------------------------------------

int main(int argc, char** argv){

    // declaram variabilele pentru a stoca ID procesului (PID) si status al procesii fii
    int pid = 0;
    int status = 0;

    // declaram variabilele pentru a parcurge argumentele date ca parametru
   
    int i = 1;            // pentru verificarea directoarelor
    int j = 1;            // pentru crearea proceselor
    int dirOutput = 0;    // daca suntem in functionalitatea -o
    int dirMove = 0;      // daca suntem in functionalitatea -s
   
    // verificam numarul de argumente date ca parametru
    if(argc < 2){
        perror("Eroare: Numar de argumente de linie de comanda gresit.\n");
        exit(EXIT);
    }
    // verificam numarul de argumente pentru extinderea funtionalitati cu -o
    if(argc < 4 && strcmp(argv[1], "-o")==0){
        perror("Eroare: Numar de argumente de linie de comanda gresit.\n");
        exit(EXIT);
    }

    // verificam daca se extinde functionalitatea codului cu "-o" si cu "-s"
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
            if(argc > 11 || argc < 2){
                perror("Eroare: Numar de argumente de linie de comanda gresit.\n");
                exit(EXIT);
            }
        }
    }

    // verificat ca parametri dati sunt diferiti
    for(int x = 0; x < argc; x++){
        for(int y = x + 1; y < argc; y++){
            if(strcmp(argv[x], argv[y]) == 0){
                fprintf(stderr, "Error: Duplicate argument %s in linea de comanda.\n", argv[x]);
                exit(EXIT);
            }
        }
    }

    // verificam ca argumentele date sunt foldere
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

    // Cream un array pentru a pastra PIDs, exitCodes si numarul de fisiere malitioase
    pid_t pids[argc - j];
    int exit_codes[argc - j];
    int malitios_codes[argc - j];

    memset(pids, 0, sizeof(pid_t) * (argc - j));
    memset(exit_codes, 0, sizeof(int) * (argc - j));
    memset(malitios_codes, 0, sizeof(int) * (argc - j));

    // cream un proces copil pentru fiecare folder dat ca parametru
    int count = 0;
    for(;j<argc;j++){

        // daca detectam -s, trecem cu j doua pozitii in fata
        if(strcmp(argv[j], "-s")==0){
            // inca o pozitie ca sa trecem de izolated_space_dir
            j++;
            continue;
        }

        int nrFisiereCorupte = 0;   // varaibila pentur nr fisiere corupte 
        int pipefd[2];              // declaram pipe

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
     
        if(pid == 0){               // procesul copil

            close(pipefd[0]);       // inchidem capatul de citire al pipe-ului
            int flag = 0;           // pentru a determina daca fisierul este malitios

            printf("In folderul %s:\n", argv[j]);

            // daca rulam cu functionalitatea -o si -s
            if(dirOutput && dirMove){
                nrFisiereCorupte = analizareFolder(argv[j],argv[2],argv[4]);
                flag = 1;
                write(pipefd[1], &flag, sizeof(flag));
                write(pipefd[1], &nrFisiereCorupte, sizeof(nrFisiereCorupte)); // scriem numarul de fisiere malitioase in pipe
            }
            // daca rulam cu functionalitatea -o
            else if(dirOutput){
                nrFisiereCorupte = analizareFolder(argv[j],argv[2],NULL);
            }
            // daca rulam normal
            else{
                nrFisiereCorupte = analizareFolder(argv[j],NULL,NULL);
            }
            
            printf("-----------------\n");
            close(pipefd[1]);       // inchidem capatul de scriere al pipe-ului    
            exit(0);
        }
        else{ //  procesul parinte
            
            close(pipefd[1]); // inchidem capatul de scriere al pipe-ului

            pids[count] = pid; // punem pid-urile in array

            int flag = 0;
            read(pipefd[0], &flag, sizeof(flag));  // citim din pipe nr de fisiere malitioase

            // citim din pipe numarul de fisiere cu potential pericol          
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
        exit_codes[k] = WEXITSTATUS(status);  // vom pune codul de iesire in tablou de exit codes
    }

    // printam daca sa creat cu succes snapshotul
    for (int l = 0; l < count; l++){
        if(exit_codes[l] == 0){
            printf("Snapshot for Directory %d created successfully.\n", l+1);
        }
    }

    // printam rezultatele pentru fiecare proces copil
    for(int i = 0; i < count; i++) {
        if(dirMove){
            printf("Child Process %d terminated with PID %d and whith %d potentially dangerous files.\n", i+1, pids[i], malitios_codes[i]);
        }else{
            printf("Child Process %d terminated with PID %d and exit code %d.\n", i+1, pids[i], exit_codes[i]);
        }
    }
    return 0;
}