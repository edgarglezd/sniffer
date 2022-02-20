#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <features.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

//-----------------------------------------------------------------------------

#define DIRECCION_MAC 17

FILE *file, *file_d_w, *file_d_r;
int n;
unsigned char trama[2048];
char direcciones_txt[2048];
char espacios[]=" \n";
int total=0, ethernet=0, ieee=0, otro=0;
int ipvcuatro=0, ipvseis=0, arp=0, controlflujo=0, seguridadmac=0;

struct p_capturador{
  int sr;
  unsigned char *tr;
  struct sockaddr *tr_i;
  socklen_t *tr_i_l;
};
struct p_analizador{
  int nn;
  unsigned char *tr;
};

struct direcciones_mac{
  char mac_addr[DIRECCION_MAC];
  int contador;
};
struct nodo{
  struct direcciones_mac direccion;
  struct nodo *sig;
};

void *capturador(void *);
void *analizador(void *);

void agregar(struct direcciones_mac direcciones);
void agregar_addr(char mac_addr[DIRECCION_MAC]);
void imprimir(void );

void usage(const char *);
int creando_socket(int);
int bind_socket_tarjeta(char *, int, int);

void print_trama(unsigned char *p, int size);
void print_prot_hex(char *, unsigned char *, int);
void print_addr_hex(FILE *, char *, unsigned char *, int);
void print_data_hex(char *, unsigned char *, int);
int validar_protocolo(unsigned char *);
void contar_protocolo(unsigned char *);
int comunicacion_addr(unsigned char *);

void proceso_sniffer(unsigned char *, int);

//-----------------------------------------------------------------------------

struct nodo *superior = NULL;

//-----------------------------------------------------------------------------

int main(int argc, char *argv[]){
  //Variables para el socket-sniffer
  int socket_raw, no_tramas=0, i=0;
  struct sockaddr trama_info;
  int trama_info_largo=sizeof(trama_info);
  //Variables para los hilos
  pthread_t hilo1, hilo2;
	pthread_attr_t atributo;
  struct p_capturador p_cap;
  struct p_analizador p_ana;
  //Validando si el programa se ejecuto correctamente
  if(argc<3){
    usage(argv[0]);
  }
  //Abriendo el fichero para guardar datos
  file=fopen("p2-_niffer.txt", "w+");
  file_d_w=fopen("p2_direcciones.txt", "w+");
  if(file==NULL){
    printf("\n------------------------------------------------------------------------------\n");
    printf("\n                    No se creo el fichero -p2-_niffer.txt- \n");
  }
  else{
    printf("\n------------------------------------------------------------------------------\n");
    printf("\n                     Se creo el fichero -p2_sniffer.txt- \n");
  }
  if(file_d_w==NULL){
    printf("\n------------------------------------------------------------------------------\n");
    printf("\n                    No se creo el fichero -p2_direcciones.txt- \n");
  }
  else{
    printf("\n------------------------------------------------------------------------------\n");
    printf("\n                     Se creo el fichero -p2_direcciones.txt- \n");
  }
  //Estableciendo atributos de los hilos
  pthread_attr_init(&atributo);
	pthread_attr_setdetachstate(&atributo, PTHREAD_CREATE_JOINABLE);
  //Creando el socket
  socket_raw=creando_socket(ETH_P_ALL);
  //Uniendo el socket con la tarjeta de red
  bind_socket_tarjeta(argv[1], socket_raw, ETH_P_ALL);
  //Obteniendo el no. de tramas a analizar
  no_tramas=atoi(argv[2]);
  //Empieza proceso de Sniffe printf("\n------------------------------------------------------------------------------\n");
  printf("\n                            Inicio del Sniffer\n");
  fprintf(file, "\n------------------------------------------------------------------------------\n");
  fprintf(file, "\n                            Inicio del Sniffer\n");
  //Haciendo uso de hilos para capturar y sincronizar
  for(i=0; i<no_tramas; i++){
    printf("\n------------------------------------------------------------------------------\n");
    printf("\nTRAMA %d\n\n", i+1);
    fprintf(file, "\n------------------------------------------------------------------------------\n");
    fprintf(file, "\nTRAMA %d\n\n", i+1);
    //Se recibe una trama: n=recvfrom(socket_raw, trama, 2048, 0, (struct sockaddr*)&trama_info, (socklen_t*)&trama_info_largo);
    p_cap.sr=socket_raw; p_cap.tr=(unsigned char *)&trama;
    p_cap.tr_i=(struct sockaddr*)&trama_info;
    p_cap.tr_i_l=(socklen_t *)&trama_info_largo;
    pthread_create(&hilo1, &atributo, capturador, (void *)&p_cap);
    pthread_join(hilo1, NULL);
    if(n<0){
      perror("recvfrom");
    }
    else{
      //Se analiza la trama: proceso_sniffer(trama, n);
      p_ana.tr=(unsigned char *)&trama; p_ana.nn=n;
      pthread_create(&hilo2, &atributo, analizador, (void *)&p_ana);
      pthread_join(hilo2, NULL);
      //Contador de tramas recibidas correctamente
      total++;
    }
  }
  fclose(file_d_w);
  printf("\n------------------------------------------------------------------------------\n");
  printf("\nTotal de tramas recibidas: %d\n", total);
  printf("Ethernet II: %d  IEEE 802.3: %d  Otro: %d\n", ethernet, ieee, otro);
  printf("IPv4: %d  IPv6: %d  ARP: %d  Control de Flujo: %d  Seguridad MAC: %d\n", ipvcuatro, ipvseis, arp, controlflujo, seguridadmac);
  printf("\n------------------------------------------------------------------------------\n");
  fprintf(file, "\n------------------------------------------------------------------------------\n");
  fprintf(file, "\nTotal de tramas recibidas: %d\n", total);
  fprintf(file, "Ethernet II: %d  IEEE 802.3: %d  Otro: %d\n", ethernet, ieee, otro);
  fprintf(file, "IPv4: %d  IPv6: %d  ARP: %d  Control de Flujo: %d  Seguridad MAC: %d\n", ipvcuatro, ipvseis, arp, controlflujo, seguridadmac);
  fprintf(file, "\n------------------------------------------------------------------------------\n");
  //Leyendo otra vez para obtener las direcciones
  file_d_r=fopen("p2-direcciones.txt", "r");
  if(file_d_r==NULL){
    printf("\nNo se pudieron recuperar las direcciones\n");
    fprintf(file, "\nNo se pudieron recuperar las direcciones\n");
  }
  else{
    printf("\nDirecciones MAC encontradas:\n");
    fprintf(file, "\nDirecciones MAC encontradas:\n");
    //Obteniendo las direcciones
    while(feof(file_d_r)==0){
      fgets(direcciones_txt, 2048, file_d_r);
    }
    char *token = strtok(direcciones_txt, espacios);
    //Agregar a la pila
    while (token!=NULL) {
      agregar_addr(token);
      token=strtok(NULL, espacios);
    }
    imprimir();
  }
  fclose(file_d_r);
  printf("\n------------------------------------------------------------------------------\n");
  printf("\n                             Fin del Sniffer\n");
  printf("\n------------------------------------------------------------------------------\n\n");
  fprintf(file, "\n------------------------------------------------------------------------------\n\n");
  fprintf(file, "\n                             Fin del Sniffer\n");
  fprintf(file, "\n------------------------------------------------------------------------------\n\n");
  fclose(file);
  close(socket_raw);
  return 0;
}

//-----------------------------------------------------------------------------

void *capturador(void *arg){
  struct p_capturador *p;
  p=(struct p_capturador *)arg;
  n=recvfrom(p->sr, p->tr, 2048, 0, (struct sockaddr*)&p->tr_i, (socklen_t*)&p->tr_i_l);
  pthread_exit(0);
}
void *analizador(void *arg){
  struct p_analizador *p;
  p=(struct p_analizador *)arg;
  proceso_sniffer(p->tr, p->nn);
  pthread_exit(0);
}

void agregar(struct direcciones_mac direccion){
  struct nodo *nuevoNodo = malloc(sizeof(struct nodo));
  nuevoNodo->direccion=direccion;
  nuevoNodo->sig=superior;
  superior=nuevoNodo;
}
void agregar_addr(char mac_addr[DIRECCION_MAC]){
  struct nodo *temporal=superior;
  while(temporal!=NULL){
    int resultadoDeComparacion=strcasecmp(temporal->direccion.mac_addr, mac_addr);
    if(resultadoDeComparacion==0){
      temporal->direccion.contador++;
      return;
    }
    temporal=temporal->sig;
  }
  struct direcciones_mac direccion;
  strcpy(direccion.mac_addr, mac_addr);
  direccion.contador=1;
  agregar(direccion);
}
void imprimir(void) {
  struct nodo *temporal=superior;
  while(temporal!=NULL){
    printf("%s: ...................................................... %.4d\n", temporal->direccion.mac_addr, temporal->direccion.contador);
    fprintf(file, "%s: ...................................................... %.4d\n", temporal->direccion.mac_addr, temporal->direccion.contador);
    temporal=temporal->sig;
  }
}

void usage(const char *arg){
	printf("%s <tarjeta de red> <no. tramas>\n", arg);
  exit(1);
}

int creando_socket(int protocolo_sniffer){
  int socket_raw;
  socket_raw=socket(PF_PACKET, SOCK_RAW, htons(protocolo_sniffer));
  if (socket_raw<0){
    perror("Error en la creacion del Socket");
    exit(1);
  }
  return socket_raw;
}
int bind_socket_tarjeta(char *device, int socket_raw, int protocolo_sniffer){
  struct ifreq eth;
  bzero(&eth, sizeof(eth));
  strncpy((char *)eth.ifr_name, device, IFNAMSIZ); //Estableciendo la tarjeta de red
  ioctl(socket_raw, SIOCGIFFLAGS, &eth);
  eth.ifr_flags |= IFF_PROMISC; //Cambiando a modo promiscuo
  ioctl(socket_raw, SIOCSIFFLAGS, &eth);
  if(socket_raw<0){
    perror("Error uniendo el socket con la tarjeta de red\n");
		exit(1);
  }
  return socket_raw;
}

void print_trama(unsigned char *packet, int size){
  unsigned char *p = packet;
  while(size--){
    printf("%.2X ", *p);
    fprintf(file, "%.2X ", *p);
    p++;
  }
}
void print_prot_hex(char *mesg, unsigned char *p, int size){
  fprintf(file, "%s", mesg);
  while(size--){
    fprintf(file, "%.2X", *p);
    p++;
  }
}
void print_addr_hex(FILE *arch, char *mesg, unsigned char *p, int size){
  int i;
  fprintf(arch, "%s",mesg);
  for(i=0; i<size; i++){
    if(i!=(size-1))
      fprintf(arch, "%.2X:", *p);
    else
      fprintf(arch, "%.2X ", *p);
    p++;
  }
}
void print_data_hex(char *mesg, unsigned char *p, int size){
  fprintf(file, "%s", mesg);
  while(size--){
    fprintf(file, "%.2X ", *p);
    p++;
  }
}
int validar_protocolo(unsigned char *p){
  int primerbyte, segundobyte;
  primerbyte=*p; p++;
  segundobyte=*p;
  if(primerbyte>=0x06)
    return 1;
  else if((primerbyte<=0x05) & (segundobyte<=0xdc))
    return 0;
  else
    return 3;
}
void contar_protocolo(unsigned char *p){
  int primerbyte, segundobyte;
  primerbyte=*p; p++;
  segundobyte=*p;
  if((primerbyte==0x08) & (segundobyte==0x00))
    ipvcuatro++;
  else if((primerbyte==0x86) & (segundobyte==0xdd))
    ipvseis++;
  else if((primerbyte==0x08) & (segundobyte==0x06))
    arp++;
  else if((primerbyte==0x88) & (segundobyte==0x08))
    controlflujo++;
  else if((primerbyte==0x88) & (segundobyte==0xe5))
    seguridadmac++;
}
int comunicacion_addr(unsigned char *p){
  int primerbyte, modulo;
  primerbyte=*p;
  modulo=primerbyte%2;
  if(modulo==0)
    return 0;
  else
    return 1;
}

void proceso_sniffer(unsigned char *packet, int size){
  //Variables para manipular la trama y la cabecera ethernet
  struct ethhdr *ethernet_header;
  unsigned char *data;
	int data_len;
  int protocolo, contador_protocolo;
  int comunicacion_fuen, comunicacion_dest;
  //Checar si hay datos en la trama
  if(size>sizeof(struct ethhdr)){
    //Obtener la cabecera de la trama
    ethernet_header=(struct ethhdr *)packet;
    protocolo=validar_protocolo((void *)&ethernet_header->h_proto);
    //Ethernet II
    if(protocolo==1){
      ethernet++;
      //Contar por tipo de protocolo
      contar_protocolo((void *)&ethernet_header->h_proto);
      //Tipo: 2 Bytes con el protocolo de la trama
  		print_prot_hex("Protocolo: ............................................................ 0x", (void *)&ethernet_header->h_proto, 2);
  		fprintf(file, "\n");
      //Fuente: 6 Bytes con la direccion MAC de la fuente
  		print_addr_hex(file, "Direccion MAC Fuente: ...................................... ", ethernet_header->h_source, 6);
  		fprintf(file, "\n");
  		//Destino: 6 Bytes con la direccion MAC del destino
  		print_addr_hex(file, "Direccion MAC Destino: ..................................... ", ethernet_header->h_dest, 6);
  		fprintf(file, "\n");
      //Longitud: +64 Bytes total de la trama
      fprintf(file, "Longitud: ............................................................... %.4d\n", size);
      //Carga Util: +46 Bytes con datos y relleno
      data=packet+sizeof(struct ethhdr);
  		data_len=size-sizeof(struct ethhdr);
      if(data_len)
        fprintf(file, "Longitud de carga util: ................................................. %.4d\n", data_len);
      else
        fprintf(file, "Longitud de carga util: ................................................. 0000\n");
      //Determinar tipo de comunicacion de la direccion fuente
      comunicacion_fuen=comunicacion_addr(ethernet_header->h_source);
      if(comunicacion_fuen==1)
        fprintf(file, "Comunicacion Direccion Fuente: ................................. Multidifusion\n");
      else if(comunicacion_fuen==0)
        fprintf(file, "Comunicacion Direccion Fuente: ................................... Unidifusion\n");
      //Determinar tipo de comunicacion de la direccion destino
      comunicacion_dest=comunicacion_addr(ethernet_header->h_dest);
      if(comunicacion_dest==1)
        fprintf(file, "Comunicacion Direccion Destino: ................................ Multidifusion\n");
      else if(comunicacion_dest==0)
        fprintf(file, "Comunicacion Direccion Destino: .................................. Unidifusion\n");
      //Imprimir trama completa
      fprintf(file, "\n");
      print_trama(packet, size);
      printf("\n");
      fprintf(file, "\n");
      //Imprimir carga util
      print_data_hex("\n", data, data_len);
      fprintf(file, "\n");
      //Almacenar direcciones mac fuente y destino
      print_addr_hex(file_d_w, "", ethernet_header->h_source , 6);
      print_addr_hex(file_d_w, "", ethernet_header->h_dest, 6);
    }
    //IEEE 802.3
    else if(protocolo==0){
      //Tipo: 2 Bytes con el protocolo de la trama
      printf("La trama no puede ser analizada\n");
      fprintf(file, "La trama no puede ser analizada\n");
      print_prot_hex("Protocolo: ............................................................ 0x", (void *)&ethernet_header->h_proto, 2);
      printf("\n\n");
    }
    else{
      otro++;
      printf("La trama no pudo ser identificada\n\n");
      fprintf(file, "La trama no pudo ser identificada\n\n");
    }
	}
	else{
		printf("Trama demasiado corta:(\n");
    fprintf(file, "Trama demasiado corta:(\n");
	}
}

