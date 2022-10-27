#include <stdio.h>
#include <string.h>

int all_accounts_balance() {
        printf("Votre don:\nMontant\n");
        return 0;
}

void donner(char *ong, int montant) {
        printf("Vous avez donné: %d, à l'ONG: %s.\n", montant, ong);
}

int main(int argc, char *argv[]){
        char ong[8];
        int montant = 50;
        printf("Bienvenue dans la Defisc BOX ;-)\n\n");
        printf("Nom de l'ONG destinatrices: ");
        gets(ong);
        donner(ong, montant);
        printf("Merci, votre don a bien été enregistré\n");
        return 0;
}
