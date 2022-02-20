#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/if.h>
#include <errno.h>

unsigned char tramaRec[1514] ;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

int indicador1,packet_socket;

typedef struct _Nodo{
char  crudo[1521];
struct _Nodo *sig;
}Nodo;


Nodo *crearNodo(char aux[1521]);
Nodo *altaFila(Nodo *frente, char aux[1521]);
Nodo *bajaFila(Nodo *frente);
void verFila(Nodo *frente);
int longitudFila(Nodo *frente);
void Imprimirfilas(Nodo *aux, Nodo *aux2, Nodo *aux3);


void imprimeTrama (unsigned char *trama, int tam ){

int i,j;

for(i=0 ;i<tam ;i++)
{
if(i%16==0)
printf ("\n"); printf ("% .2x ",trama [i-1]);
}
printf ("\n");
}

Nodo *Tramas=NULL;


void *hilo_capturar(void *unused){

printf("\nIngresando al hilo 1 \n");
int h1=0,tam;

while(h1<indicador1){

tam=recvfrom(packet_socket,tramaRec,1514,0,NULL,0);
if(tam==-1)
{
perror("\nError al recibir"); 
exit(0);
}
else{

printf("\nExito al recibir la trama");
printf ("\n La trama detectada es\n");

imprimeTrama(tramaRec,60);

pthread_mutex_lock(&mutex);
Tramas=altaFila(Tramas,tramaRec);
pthread_mutex_unlock(&mutex);


h1= h1 + 1;
}
}

}

void *hilo_analizar(void *unused){
/*
int h2=0,y=0,len,p,i;
char Localbuf [1521]="";
Nodo *Local=NULL;


//while(h2 < indicador1){
for(i=0; i<6000; i+=1){

len = longitudFila(Tramas);
printf(" %d ", len);
if(len!=0){

pthread_mutex_lock(&mutex);
Local=Tramas;
pthread_mutex_unlock(&mutex);

for(p=0; p<len-1; p=p+1){

printf("\nIngresando al for \n");
Local = Local->sig;

}

strcpy(Localbuf, Local->crudo);
printf("\nIngresando al archivo \n");

pthread_mutex_unlock(&mutex);


h2=len;



//}
}
}
*/
}






int main ()
{
pthread_t capturador, analizador;


char adapatador_red[20];

struct ifreq ethreq;
int y,tam,h=0;


printf("Ingresa nombre del adaptador de red: \n");

gets(adapatador_red);


packet_socket=socket(AF_PACKET,SOCK_RAW ,htons(ETH_P_ALL)); 

strncpy(ethreq.ifr_name, adapatador_red, IFNAMSIZ);

ioctl(packet_socket, SIOCGIFFLAGS, &ethreq);

ethreq.ifr_flags |= IFF_PROMISC;

y=ioctl(packet_socket, SIOCSIFFLAGS, &ethreq);

if (y<0)
{
perror("Error al establecer la tarjeta de red");
}

if (packet_socket==-1)
{
perror("\nError al abrir el socket");
exit (0);
}
else
{
perror("Exito al abrir el socket"); 

printf("\n Ingresar el numero de tramas a capturar:  \n");
scanf("%d",&indicador1);




if(0 != pthread_create(&capturador, NULL, hilo_capturar, NULL)){

printf("Error pthread");
return -1;

}


if(0 != pthread_create(&analizador, NULL, hilo_analizar, NULL)){

printf("Error pthread2");
return -1;
}

pthread_join(capturador, NULL);

pthread_join(analizador, NULL);


}
close (packet_socket); 
return -1;
}





Nodo *crearNodo(char aux[1521]){
Nodo *nuevo;
char ol[1521]="";
nuevo=(Nodo *) malloc(sizeof(Nodo));
strcpy(nuevo->crudo,ol);
strcat(nuevo->crudo,aux);
nuevo->sig=NULL;
return nuevo;
}



Nodo *altaFila(Nodo *frente, char aux[1521]){
Nodo *cajita;
Nodo *cima;
cima=frente;
cajita=crearNodo(aux);
if(cima==NULL){
    frente=cajita;
              }
              else{
                    while(cima->sig!=NULL){

                        cima=cima->sig;
                    }
                cima->sig=cajita;
              }
    return frente;
}


Nodo *bajaFila(Nodo *frente){
Nodo *destruir;
destruir=frente;
if(frente==NULL){
    return frente;
}
frente=frente->sig;
free(destruir);
return frente;
}


void verFila(Nodo *frente){
Nodo *aux;
aux=frente;
while(aux!=NULL){
    printf("\n\t%s\n", aux->crudo);
    aux=aux->sig;
}
}


int longitudFila(Nodo *frente){
    int contador=0;
Nodo *aux;
aux=frente;
while(aux!=NULL){

contador ++;
    aux=aux->sig;
}

return contador;
}



void Imprimirfilas(Nodo *aux, Nodo *aux2, Nodo *aux3){

Nodo *fila1, *fila2, *fila3;
fila1=aux;
fila2=aux2;
fila3=aux3;
	printf("\nDocumentos mandados a imprimir\n");
	printf("\n\tEqui1\tEqui2\tEqui3\n");
while(fila1!=NULL && fila2!=NULL && fila3!=NULL){
	printf("\n\t%s",fila1->crudo);
	printf("\t%s",fila2->crudo);
	printf("\t%s",fila3->crudo);
		
	fila1=fila1->sig;
	fila2=fila2->sig;
	fila3=fila3->sig;
	}
	printf("\n");
}
