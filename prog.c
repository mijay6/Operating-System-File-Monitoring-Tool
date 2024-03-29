// Programul va primi un folder, va parcurge recursiv folderul, poate avea si subfoldere
// Va trebui sa verfice ce s-a schimbat de la prima rulare a programului la a doua in folder orice, o linie de fisier, nume, etc.


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#define EXIT -1


// functia pentru deschidere folder

DIR *deschideFolder(const char *nume){

    DIR *folder;

    if ((folder = opendir(nume)) == NULL){
        perror("EROARE: Deschidere fisier.\n");
        exit(EXIT);
    }
    return folder;
}

// functia pentru inchidere folder

void *inchideFolder(DIR *folder){

    if(closedir(folder) != 0){
        perror("EROARE: Inchidere fisier.\n");
        exit(EXIT);
    }

}

// se da ca parametru in linie de comanda folderul

int main(int argc, char** argv){

    // verificam ca numarul de argument dat ca parametru e corect

    if(argc != 2){
        perror("Eroare: Numar de argumente de linie de comanda gresit.\n");
        exit(EXIT);
    }

    // vom apela functia pentru a deschide folderul

    DIR *folder;

    folder = deschideFolder(argv[1]);

    // vom apela functia pentru a inchide folderul

    inchideFolder(folder);

    // parcurgem folderul

    // facem un apel de functie sistem  pentru a citi din folder

    struct dirent*;

    dirent = readdir(folder);




   // int open(const char *pathname, int oflag, [, mode_t mode]);

    
}