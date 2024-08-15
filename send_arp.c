#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

/* 쌍 정하기 */
#define MAX_PAIR 5

/*arp 헤더*/
struct ethernet {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
} __attribute__((__packed__));
/*arp 헤더*/
struct arp_header {
    uint16_t Hardware_type;
    uint16_t Protocol_type;
    uint8_t Hw_addlen;
    uint8_t Pro_addlen;
    uint16_t Operation;  //1 == request 2 == reply
    uint8_t Src_hwadd[6]; //mac
    uint8_t Src_proadd[4]; //ip
    uint8_t Dst_hwadd[6]; //mac
    uint8_t Dst_proadd[4]; //ip;
} __attribute__((__packed__));


/*패킷 합체*/
struct {
   struct ethernet eth;
   struct arp_header arp;
} packet; 
//eth + arp == packet

/*오류 메시지*/
void usage() {
   printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
   printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

/*찐 시작 */
int main (int argc, char *argv[]) {
   /*짝수 개수 일때만*/
   if (argc < 4 || argc % 2 != 0)
   {
      usage();
      return -1;
   }

   char* dev = argv[1]; //네트워크
   int num_pair = (argc - 2) / 2; //쌍 개수
   char* sender[num_pair]; //sender만
   char* target[num_pair]; //target 만
   char errbuf[PCAP_ERRBUF_SIZE];
   

   pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf); //핸들
   if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
      return -1;
   }

   /* 진짜 시작 */
   for (int i = 0; i < argc; i++){
      if (i > 1)
      {
         if (i % 2 == 0) //[프로그램] [네트워크] [sender] [target]
         {
            sender[(i - 2)/2] = argv[i]; //짝수면
         }
         else
         {
            target[(i - 2) / 2] = argv[i]; // 홀수면 
         }
      }
   }
   /*패킷 설정*/
   packet.eth.type = htons(0x0806); //0806 == arp
   packet.arp.Hardware_type = htons(1); //하드웨어 타입 1 == 이더넷
   packet.arp.Protocol_type = htons(0x0800); //프로토콜 타입 800 == ip 
   packet.arp.Hw_addlen = 6;
   packet.arp.Pro_addlen = 4;
   packet.arp.Operation = htons(0x0001); //arp request임 
   memset(packet.eth.dst, 0xff, 6); //ethernet dst mac ff채우기
   memset(packet.arp.Dst_hwadd, 0x00, 6); //arp dst mac 00채우기

   for (int i = 0 ; i < num_pair ; i++){

      /* 가져온거 */
      // MAC 주소를 가져오기 위해 필요한 소켓 설정
      int fd = socket(AF_INET, SOCK_DGRAM, 0);
      if (fd == -1) 
      {
         perror("socket");
         return EXIT_FAILURE;
      }
      struct ifreq ifr;
      memset(&ifr, 0, sizeof(ifr));
      strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
      // ioctl을 통해 인터페이스의 MAC 주소 가져오기
      if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
         perror("ioctl");
         close(fd);
         return EXIT_FAILURE;
      }
      close(fd);
      // MAC 주소를 패킷 구조체에 복사
      memcpy(packet.eth.src, ifr.ifr_hwaddr.sa_data, 6);
      memcpy(packet.arp.Src_hwadd, ifr.ifr_hwaddr.sa_data, 6);
      /* 가져온거 끝 */

      /* text 형식을 ip 형식으로 변신 */
      inet_pton(AF_INET, sender[i], packet.arp.Src_proadd);
      inet_pton(AF_INET, target[i], packet.arp.Dst_proadd);
      
      /* 패킷날리기 */
      if (pcap_sendpacket(handle, (const u_char*)&packet, sizeof(packet)) != 0) {
         fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
         pcap_close(handle);
         return EXIT_FAILURE;
      }
      printf("sender: %s, target: %s\n", sender[i], target[i]); 
   }
   pcap_close(handle);
}
