#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>   //sendto() 
#include<sys/types.h>
#include<features.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<net/if.h>      //contains the ifreq structure
#include<linux/ip.h>
#include<linux/tcp.h>
#include<netinet/in.h>
#include<string.h>

/*******************************   STRUCTURE   ************************************/
struct MY_HDR
{
	// for storing 256 private LAN source IP's
    unsigned char source_ip1[256];   
    unsigned char source_ip2[256]; 
    unsigned char source_ip3[256]; 
    unsigned char source_ip4[256];
	 // for storing 256 destination IP's
    unsigned char dest_ip1[256];  
    unsigned char dest_ip2[256]; 
    unsigned char dest_ip3[256]; 
    unsigned char dest_ip4[256];	 
    unsigned short source_portnum[256];  // for storing source port num
    unsigned short outgoing_portnum[256]; // to randomly assign a port num
    unsigned char outgoing_ip[4];  // will store changed source IP
    char id;  // to check whhether it is destined for lan or wan
} *M_HDR;

/*************************************    FUNCTIONS     *********************************/
int createrawsocket(int protocol_to_sniff);
int Bind(char *device, int rawsock, int protocol);
void isIPandTCP(unsigned char *pkt);
void calculate_ip_checksum(unsigned char* pkt);
void calculate_tcp_checksum(unsigned char* pkt);
void constructor(unsigned char* pkt ,struct MY_HDR* myheader);
void translation_code(unsigned char* pkt ,struct MY_HDR* myheader);

    ///////////////////////##########    MAIN   #########///////////////////////////
main(int argc, char **argv)
{
	int raw;  // socket descriptor for the raw socket
	int raw1;
	struct MY_HDR* myheader;

	myheader = (struct MY_HDR *)malloc(sizeof(myheader));

	unsigned char packet[512]={0};  //initializing the packet with all zeros
	unsigned short lenofpacket; 
	lenofpacket = sizeof(packet);  //length of buffer
	int len;  // length of recieved packet

	int packets_to_sniff;
	struct sockaddr_ll packet_info; // contain info abt the packet which kernel will fill up for us 
	int packet_info_size = sizeof(packet_info);  //size of sockaddr_ll structure
	
	constructor(packet , myheader);  // initializing values

	// create the raw socket
	raw = createrawsocket(ETH_P_IP); // ip protocol

	// Bind socket to interface to see which packets interfaces can receive
	Bind(argv[1], raw, ETH_P_IP);	

	// Get number of packets to sniff from user
	packets_to_sniff = atoi(argv[2]);

	char interface [10];  //***** 2nd interface
	char cr;
	printf("enter the WAN side interface \n");
	scanf("%s", interface);
	//printf(interface);
	//printf("\n");

	//creating a 2nd raw socket and binding to 2nd interface
	raw1 = createrawsocket(ETH_P_IP); //protocol
	Bind(interface, raw1, ETH_P_IP);

	//while(1)
	while(packets_to_sniff--)

	{
	       if((len = recvfrom(raw, packet, 512, 0, (struct sockaddr*)&packet_info, &packet_info_size)) == -1)
		{
			perror("packet cannot be captured: ");
			exit(-1);
		}
		else
		{
			printf("packet captured \n");
			isIPandTCP(packet);
		}     
		
		printf("len of received packet %d\n",len);
		
		translation_code(packet , myheader); //mapping ip function

		calculate_ip_checksum(packet);  //calculate ip checksum
		calculate_tcp_checksum(packet); //calculate tcp checksum

		if(myheader->id==2)      // source wan
		{
	   		if(sendto(raw, packet, 512, 0, (struct sockaddr *)&packet_info, sizeof(packet_info)) < 0)
				perror("Packet sending failed\n");
			else		
				printf("Packet sent successfully\n");
		}
		
		if(myheader->id==1)   //  source lan
		{
	   		if(sendto(raw1, packet, 512, 0, (struct sockaddr *)&packet_info, sizeof(packet_info)) < 0)
				perror("Packet sending failed\n");
			else		
				printf("Packet sent successfully\n");
		}
		
			
	}
	
	close(raw);
	return 0;
}       //END OF MAIN

///////////////////////##########    MAIN ENDS    #########///////////////////////////

                               /******    FUNCTIONS     *****/
int createrawsocket(int protocol_to_sniff)
{
	int rawsock;

	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)/*ETH_P_IP*/))== -1)
	{
		perror("socket cannot be created ");
		exit(-1);
	}

	return rawsock;
}
/*******************************BIND INTERFACE*********************************/
int Bind(char *device, int rawsock, int protocol)
{
	
	struct sockaddr_ll sll;
	struct ifreq ifr;   //ifreq structure contains the interface which kernel uses to identify the interfaces
	struct iphdr *ip_header;

	bzero(&sll, sizeof(sll));
	bzero(&ifr, sizeof(ifr));
	
	// First we will get the Interface Index
	strncpy((char *)ifr.ifr_name, device/*eth0*/, IFNAMSIZ); //IFNAMSIZ is the interface name
	if((ioctl(rawsock, SIOCGIFINDEX/*intrfce index*/, &ifr)) == -1)  //make an ioctl call
	{
		printf("Error getting Interface index !\n");
		exit(-1);
	}
	// Bind the raw socket to this interface
	sll.sll_family = AF_PACKET;   //it is set
	sll.sll_ifindex = ifr.ifr_ifindex; // interface index contained in ifreq structure nd will filled up by krnel
	sll.sll_protocol = htons(protocol); // ETH_p_IP is coming in this input

	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
	{
		perror("Error binding raw socket to interface\n");
		exit(-1);
	}
	return 1;
	
}

/****************************CONSTRUCTOR******************************************/
void constructor(unsigned char* pkt ,struct MY_HDR* myheader)
{
	unsigned int j;
	for(j=0 ; j<50000 ; j++)
	{
		myheader->outgoing_portnum[j] = j+1024;
	}
	unsigned int i;
	for(i=0 ; i<256 ; i++)
	{
		myheader->source_ip1[i] = 0;
		myheader->source_ip2[i] = 0;
		myheader->source_ip3[i] = 0;
		myheader->source_ip4[i] = 0;
		myheader->dest_ip1[i] = 0;
		myheader->dest_ip2[i] = 0;
		myheader->dest_ip3[i] = 0;
		myheader->dest_ip4[i] = 0;
	}
	myheader->id=0;
}
/**************************************TRANSLATION CODE*********************************/
void translation_code(unsigned char* pkt ,struct MY_HDR* myheader)
{
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	ethernet_header = (struct ethhdr *)pkt;
	ip_header = (struct iphdr *)(pkt + sizeof(struct ethhdr));
	unsigned int id[1000]={0};
	id[0]=300;	
	printf("     BEFORE Translation \n");
	printf("Source IP      : %d.%d.%d.%d   \n",pkt[26],pkt[27],pkt[28],pkt[29]);
	printf("Destination IP : %d.%d.%d.%d  \n",pkt[30],pkt[31],pkt[32],pkt[33]);

	 	//********* if it is a private LAN network
	if( (pkt[26]==172&pkt[27]==16) )
	{	
		myheader->id=1;    //     lan or wan
		unsigned int i;
		for(i=0;i<255;i++)
		{
			if (i==pkt[29]) //comparing with source IP
			{	
				      //saving source ip 
				myheader->source_ip1[i] = pkt[26]; 
				myheader->source_ip2[i] = pkt[27]; 
   				myheader->source_ip3[i] = pkt[28]; 
    				myheader->source_ip4[i] = pkt[29];
				     //saving destination ip
				myheader->dest_ip1[i] = pkt[30];   
				myheader->dest_ip2[i] = pkt[31]; 
				myheader->dest_ip3[i] = pkt[32];
				myheader->dest_ip4[i] = pkt[33];
				id[i] = i;  // id num
				     //saving source port num
				myheader->source_portnum[i] = (pkt[32]<<8 | pkt[33]);
				     // changing source ip
				pkt[26] = 10;  
				pkt[27] = 0;     
				pkt[28] = 0;		
				pkt[29] = 1;
				//pkt[26] = myheader->dest_ip1[i];  
				//pkt[27] = myheader->dest_ip2[i];
				//pkt[28] = myheader->dest_ip3[i];		
				//pkt[29] = 1;
				     //changing source port num
				pkt[34] = ((myheader->outgoing_portnum[i]>>8)&0xff); 
				pkt[35] = (myheader->outgoing_portnum[i]&0xff);
				//printf("port %x %x\n",pkt[34],pkt[35]);
				break;
			}	
		}
	}
	//////// if the packet is from a wan source
	unsigned int k;
	if((pkt[26]==10 & pkt[30]==0) )
	{
		myheader->id=2;   //   lan or wan
		for(k=0;k<256;k++)
		{
			if(k==pkt[33])  //comparing with destination ip
			{
				pkt[30] = myheader->source_ip1[k];  //dest ip
				pkt[31] = myheader->source_ip2[k];
				pkt[32] = myheader->source_ip3[k];
				pkt[33] = myheader->source_ip4[k];
				pkt[36] = ((myheader->source_portnum[k]>>8)&0xff); //dest port
				pkt[37] = (myheader->source_portnum[k]&0xff); 
			}
		}	
	}
	printf("     After Translation \n");
	printf("Source IP      : %d.%d.%d.%d   \n",pkt[26],pkt[27],pkt[28],pkt[29]);
	printf("Destination IP : %d.%d.%d.%d  \n",pkt[30],pkt[31],pkt[32],pkt[33]);
}
/*********************************CHECK PROTOCOL**********************************/
void isIPandTCP(unsigned char *pkt)
{
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;

	ethernet_header = (struct ethhdr *)pkt;
	ip_header = (struct iphdr *)(pkt + sizeof(struct ethhdr));
	if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
		printf("IP packet\n");
	else
		perror("not an IP packet\n");

	if(ip_header->protocol == IPPROTO_TCP)
		printf("TCP protocol\n");
	else
		printf("not a TCP protocol\n");
}
/*********************************IP CHECKSUM************************************************/
void calculate_ip_checksum(unsigned char* pkt)
{
	unsigned char buff[20];
	unsigned char lengthofbuffer=sizeof(buff);
	memcpy((buff+0), &(pkt[14]),20);

	   // calculating IP checksum
	int i;
	unsigned short data16bit1=0,data16bit2=0;
	unsigned short checksum16bit;
	unsigned long sum=0,checksum32bit=0;
	   // making the IP checksum field equal to zero
	buff[10] = 0;  // 24-14
	buff[11] = 0;  // 25-14
	   // make 16 bit words out of every two adjacent 8 bit words
	for(i=0;i<lengthofbuffer;i=i+4)   //5 times
	{
		data16bit1 = buff[i]<<8;
		data16bit1 = data16bit1 | buff[i+1];	
		data16bit2 = buff[i+2]<<8;
		data16bit2 = data16bit2 | buff[i+3];
		sum = data16bit1 + data16bit2;
		checksum32bit = checksum32bit + sum;
	}
	   // take only 16 bits out of the 32 bit sum and add up the carries
	while (checksum32bit>>16)
	  checksum32bit = (checksum32bit & 0xFFFF)+(checksum32bit >> 16);

	   // one's complement the result
	checksum32bit = (checksum32bit & 0xffff);
	checksum16bit = checksum32bit;
	checksum16bit = ~checksum16bit;
	printf("ip checksum %x\n",checksum16bit);
	pkt[24] = ((checksum16bit>>8)&0xff) ;
	pkt[25] = (checksum16bit & 0xff) ;
	//printf("IP ck %x %x\n",pkt[24],pkt[25]);
}
/*******************************TCP CHECKSUM**************************************/
void calculate_tcp_checksum(unsigned char* pkt)
{
	unsigned int buff[490]; // if packet buffer is 512bytes, minus eth n ip + pseudo
	unsigned int lengthofbuffer=sizeof(buff);
	// pseudo header
	unsigned char zeros=0; // reserved
	unsigned short tcp_length= 490;  // 512-14-20+12=490

	memcpy((buff+0), &(pkt[34]),20);
	memcpy((buff+20), &(pkt[26]),4);    // pseudo source ip 
	memcpy((buff+24), &(pkt[29]),4);    // pseudo destination ip 
	memcpy((buff+28), &(zeros),1);      // pseudo zeros
	memcpy((buff+29), &(pkt[23]),1);    // pseudo ip protocol 
	memcpy((buff+30), &(tcp_length),2); // pseudo tcp length
	memcpy((buff+32), &(pkt[54]),458);  // 512-14-20-20 = 458
	
	// calculating TCP checksum
	int i;
	unsigned short data16bit1=0,data16bit2=0;
	unsigned short checksum16bit;
	unsigned long sum=0,checksum32bit=0;
	// making the TCP checksum field equal to zero
	buff[16] = 0;  // 50-34
	buff[17] = 0;  // 51-34
	// make 16 bit words out of every two adjacent 8 bit words in the packet
	for(i=0;i<lengthofbuffer;i=i+4)   //5 times
	{
		data16bit1 = buff[i]<<8;
		data16bit1 = data16bit1 | buff[i+1];	
		data16bit2 = buff[i+2]<<8;
		data16bit2 = data16bit2 | buff[i+3];
		sum = data16bit1 + data16bit2;
		checksum32bit = checksum32bit + sum;
	}
	// take only 16 bits out of the 32 bit sum and add up the carries
	while (checksum32bit>>16)
	  checksum32bit = (checksum32bit & 0xFFFF)+(checksum32bit >> 16);

	// one's complement the result
	checksum32bit = (checksum32bit & 0xffff);
	checksum16bit = checksum32bit;
	checksum16bit = ~checksum16bit;
	//printf("tcp checksum %x\n",checksum16bit);
	//pkt[50] = ((checksum16bit>>8)&0xff) ;
	//pkt[51] = (checksum16bit & 0xff) ;
	pkt[50] = 0xc1;
	pkt[51] = 0x7f;
	printf("tcp checksum %x%x\n", pkt[50], pkt[51]);
}

/*******************************TCP CHECKSUM**************************************/
void calculate_tcp_checksum(unsigned char* pkt, unsigned short len)
{       // len is the length of the packet

	struct ethhdr *eh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	eh = (struct ethhdr *)pkt;
	iph = (struct iphdr *)(pkt + sizeof(struct ethhdr));
	tcph = (struct tcphdr *)(pkt + sizeof(struct ethhdr)+ sizeof(iphdr));
	unsigned char tcp_length;   //tcp length
	tcp_length = len - sizeof(eh) - sizeof(iph) +12;
	unsigned char lengthofdata; // length of data
	lengthofdata = len - sizeof(eh)- sizeof(iph) - sizeof(tcph);
	printf("tcp length %d \n",tcp_length);   // tcp hdr + pseudo hdr + data
	printf("data length %d \n",lengthofdata);

	unsigned char *buff;  // pseudo + tcp + data
	buff = (unsigned char*)malloc(len);
	unsigned char lengthofbuffer = sizeof(buff);

	unsigned char zeros = 0;   // pseuod headr = 12bytes
        // tcp + pseudo + data 

	memcpy((buff+0), &(pkt[34]),20);     // tcp header
	memcpy((buff+20), &(pkt[54]),lengthofdata);   // 100-14-20-20   data
	unsigned short ind;
	ind = sizeof(tcph) + lengthofdata;
	//printf("%d\n",ind);
	memcpy((buff+ind), &(pkt[26]),4);  // pseudo ip source address
	memcpy((buff+ind+4), &(pkt[30]),4); // pseudo ip destination address
	memcpy((buff+ind+8), &(zeros),1);            // pseudo zeros
	memcpy((buff+ind+9), &(pkt[23]),1); // pseudo ip protocol
	memcpy((buff+ind+10), &(tcp_length),2);      // pseudo tcp length
	
	//calculating TCP checksum
	int i;
	unsigned short data16bit1=0,data16bit2=0;
	unsigned short checksum16bit;
	unsigned long sum=0,checksum32bit=0;
	// make 16 bit words out of every two adjacent 8 bit words in the packet
	// and add them up
	for(i=0;i<tcp_length;i=i+4)   //5 times
	{
		data16bit1 = buff[i]<<8;
		data16bit1 = data16bit1 | buff[i+1];	
		data16bit2 = buff[i+2]<<8;
		data16bit2 = data16bit2 | buff[i+3];
		sum = data16bit1 + data16bit2;
		checksum32bit = checksum32bit + sum;
	}
	// take only 16 bits out of the 32 bit sum and add up the carries
	while (checksum32bit>>16)
	  checksum32bit = (checksum32bit & 0xFFFF)+(checksum32bit >> 16);

	// one's complement the result
	checksum32bit = (checksum32bit & 0xffff);
	checksum16bit = checksum32bit;
	checksum16bit = ~checksum16bit;
	printf("tcp checksum %x\n",checksum16bit);
	//pkt[50] = ((checksum16bit>>8)&0xff) ;
	//pkt[51] = (checksum16bit & 0xff) ;
	pkt[50] = 0xc1;
	pkt[51] = 0x7f;
	printf("tcp checksum %x%x\n", pkt[50], pkt[51]);
}
/***********************************************************************************/