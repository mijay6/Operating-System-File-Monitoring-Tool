# SO_2_1_Dobra_Mihai

## Name
Proiect S0.

## Description
Acest program va analiza o serie de foldere si in functie de cum se apeleaza programul,
va realiza diferite functionalitati in aceste foldere.

## Installation
Va fi compilat asa: gcc -Wall -o prog prog.c -lssl -lcrypto

## Usage

./prog folder1 folder2 folder3...etc (maxim 10 directoare)

Se da ca parametru unul sau mai multe foldere si programul va calcula suma de control SHA-256
a tuturor fisierelor din folder si subfoldere si va pastra metadatele fiecarei fisiere din folder
intrun fisier snapshot. Va compara snapshotul anterior cu cel actual si va printa modificarile.
---------------------------------------------------------------------- 
./prog -o outputdir folder1 folder2 folder3...etc (maxim 10 directoare)

Functionalitatea este extinsa cu un parametru -o urmat de un folder unde 
se vor pune fisierele snapshot ale folderelor date ca parametru
----------------------------------------------------------------------
./prog -o outputdir -s izolated_space_dir folder1 folder2 folder3...etc (maxim 10  directoare)

Functionalitatea este extinsa cu un parametru -s urmat de un folder unde se vor muta fisierele malitioase
----------------------------------------------------------------------

## Authors and acknowledgment
Dobra Mihai

## License
Open Source

## Project status
Finish