// Programul va primi un folder, va parcurge recursiv folderul, poate avea si subfoldere
// Va trebui sa verfice ce s-a schimbat de la prima rulare a programului la a doua in folder orice, o linie de fisier, nume, etc.
//----------------------------------------------------------------------
// ATENTIE: va fi compilat asa: gcc -Wall -o prog prog.c -lssl -lcrypto
//----------------------------------------------------------------------

// TODO: Cerinta Lab7

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

#define EXIT -1
#define MAX_FILES 1000
#define BUF_SIZE 4096
#define SHA256_DIG_LENGTH 32

// Structura de date pentru nume si cheksum a unui fisier

typedef struct{
    char numeFisier[PATH_MAX];
    unsigned char hash[SHA256_DIG_LENGTH];
    int isDir;
} SnapshotEntry;

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

        // ignoram directorul cel parinte

        if(strcmp(entry->d_name,".") == 0 || strcmp(entry->d_name,"..") == 0 || strcmp(entry->d_name,"snapshot.dat") == 0){
            continue;
        }

        // bagam in variabila cale calea folderul si numele de fisier
        // pentru a construi nua cale relativa

        char cale[PATH_MAX];
        snprintf(cale,sizeof(cale),"%s/%s",nume,entry->d_name);

        // printf("Fisier: %s\n", cale);

        // aflam atributele fisierului, in acest caz ce tip de inregistrare e

        struct stat statbuf;
        if(lstat(cale,&statbuf) == -1){
            fprintf(stderr,"EROARE: la citirea atributelor fisierului %s ", entry->d_name);
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

            // calculamm suma de control SHA-256 a fisierului

            if(calculeazaSHA256(cale,snapshot[*count].hash)){
                (*count)++;
            }else{
                fprintf(stderr,"Eroare la calularea sumei de control ai fisierului %s.\n", cale);
                continue;
            }
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

        //    printf("Vechi:%s\n",snapshot2[j].numeFisier);

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
                    } /*else if (snapshot1[i].isDir == 0 && memcmp(snapshot1[i].hash, snapshot2[j].hash, SHA256_DIGEST_LENGTH) != 0) {
                        modificareFolder = 1;
                        printf("Elementul %s a fost modificat: hash-ul s-a schimbat.\n", snapshot1[i].numeFisier);
                    }*/
                    break;
                }  
            }
        }
        if (!gasit && (snapshot1[i].isDir == 0)) {
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

void analizareFolder(const char *nume){

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

    if (citesteSnapshot(nume,"snapshot.dat", snapshot_anterior, &count_anterior)) {
        // Facem comparatia intre snapshotul anterior si cel actual
        comparaSnapshoturi(snapshot, count, snapshot_anterior, count_anterior);
    } else{
        printf("Prima rulare, deci nu exista un snapshot anterior.\n");
    }

    // scriem snapshotul actualizat intr-un fisier in directorul care il analizam

    if (!scrieSnapshot(nume,"snapshot.dat", snapshot, count)){
        perror("EROARE: Creare fisier snapshot.\n");
        inchideFolder(folder);
        exit(EXIT);
    }

}


// se da ca parametru in linie de comanda folderele

int main(int argc, char** argv){

    // verificam ca numarul de argument dat ca parametru e corect

    if(argc > 11){
        perror("Eroare: Numar de argumente de linie de comanda gresit.\n");
        exit(EXIT);
    }

    // verificam ca argumetele date ca parametru sunt directoare

    // TODO: mai trebue verificat ca parametri sunt diferiti

    for(int i = 1; i < argc; i++){
        DIR *dir = opendir(argv[i]);
        if (dir) {
            closedir(dir);
        } else {
            fprintf(stderr,"EROARE: %s nu este un folder sau nu poate fi deschis.\n", argv[i]);
            closedir(dir);
            exit(EXIT);
        }
    }

    // apelam functia pentru a prelucra folderul in fiecare dat ca parametru

    for(int j = 1; j < argc; j++){
        printf("In folderul %s:\n", argv[j]);
        analizareFolder(argv[j]);
        printf("-----------------\n");
    }

    return 0;
}