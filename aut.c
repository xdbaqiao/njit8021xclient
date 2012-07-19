/*************************************************************************
* File Name: Aut.c
* Author: Bingo
* Mail: baqiaoyancao@163.com
* Created Time: 2012年07月16日 星期一 14时42分06秒
*************************************************************************/

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <assert.h>

#include <openssl/md5.h>

#include "8021X.h"

static int GetHostMAC(struct userinfo *info);
static int PacketStart(pcap_t *handle);
static int sendResponseNotify(pcap_t *handle, uint8_t *ethhr, int8_t *captured);
static int sendResponseIdentity(pcap_t *handle, uint8_t *ethhr,\
        int8_t *captured, struct userinfo *info);
static int FillClientVersion(uint8_t packet[]);
static int FillWindowsVersion(uint8_t packet[]);
static int XOR(uint8_t packet[],unsigned int plen,char H3C_KEY[],unsigned int klen);
static int sendResponseMD5(pcap_t *handle, uint8_t *ethhr, int8_t *captured, struct userinfo *info);


uint8_t hostmac[6];
typedef enum{REQUEST =1, RESPONSE = 2, SUCCESS =3, FAILURE =4}EAP_CODE;
typedef enum{IDENTITY =1, NOTIFICATION = 2, NAK =3, MD5 =4, AVAILABLE = 20}EAP_TYPE;
const uint8_t DestMAC[6]={0x01,0x80,0xc2,0x00,0x00,0x03}; //多播时的MAC地址
const char H3C_KEY[] = "HuaWei3COM1X";
const char H3C_VERSION[16] = "EN V2.40-0335";
uint8_t ipadress[4]={0};


int Authentication(struct userinfo *info)
{
    const int TIME_OUT = 60000; //延时,单位ms
    bool serverResponse = false;
    char *erbuf;
    struct pcap_pkthdr *header;
    struct bpf_program *fp;
    int8_t *captured;
    uint8_t ethhr[14];
    int packetIndicate;
    pcap_t *handle;


    /*打开网卡*/
    handle = pcap_open_live(info->devname,65536,1,TIME_OUT,erbuf);
    if(handle ==NULL)
    {
        fprintf(stderr,"%s\n",erbuf);
        exit(-1);
    }
    else printf("Net is working!\n");


    /*设置过滤器*/
    char FilterStr[100];
    sprintf(FilterStr,"(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",\
            hostmac[0],hostmac[1],hostmac[2],hostmac[3],hostmac[4],hostmac[5]);
    pcap_compile(handle, fp, FilterStr, 1, 0xff);
    pcap_setfilter(handle, fp);


    /*获取本机的MAC地址*/
    if( !GetHostMAC(info) )
    {
        printf("MAC:%02x:%02x:%02x:%02x:%02x:%02x\n",\
                hostmac[0],hostmac[1],hostmac[2],hostmac[3],hostmac[4],hostmac[5]);
    }
    else 
    {
        printf("Get MAC Failure!\n");
        return 1;
    }


    /*尝试连接
     *发送EAPoL-start*/
    PacketStart(handle);
    printf("[ ]Client: Start.\n");


    /*等待服务器回应*/
    while(!serverResponse)
    {
        packetIndicate = pcap_next_ex(handle, &header, &captured);
        if( packerIndicate == 1 && (EAP_CODE)capture[18] == REQUEST)
        {
            serverResponse = true;
        }
        else
        {
            sleep(1);
            printf("."); //没有定时策略,会一直等待,直到服务器响应或者杀死进程
            PacketStart( handle);
        }
    }

    /*服务器回应之后的应答
     * EAP Response/identity */

   //先填充包头 
    memcpy(ethhr, captured+6, 6);
    memcpy(ethhr+6, hostmac, 6);
    ethhr[12] = 0x88; 
    ethhr[13] = 0x8e; 

    if((EAP_TYPE)captured[22] == NOTIFICATION)
    {
        printf("[%d] Server: Response Notification!\n",captured[19]);
        sendResponseNotify(handle ,ethhr, captured);  //其中进行版本号检测
        printf("     Client: Response Notification!\n");
        assert((pcap_next_ex(handle,&header, &captured))==1);
    }

    if((EAP_TYPE)captured[22] == IDENTITY)
    {
        printf("[%d] Server: Response Identity!\n",captured[19]);
        //获取IP?
        sendResponseIdentity(handle ,ethhr, captured, info);
        printf("[%d] Client: Response Identity!\n",captured[19]);
    }

    /*重设过滤器*/
    sprintf(FilterStr,"(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)"\
           captured[6], captured[7], captured[8], captured[9], captured[10], captured[11]);
    pcap_compile(handle, fp, FilterStr, 1, 0xff);
    pcap_setfilter(handle, fp);
    
    
    /*认证,接收服务器的密码验证,并发送*/
    while(1)
    {
        /*獲取下一個數據包*/
        while(pcap_next_ex(handle, &header, &captured) !=1)
        {
            printf(".");
            sleep(1);
        }
        /*分情況處理 */
        if((EAP_TYPE)captured[18] == REQUEST)
        {
            switch((EAP_CODE)captured[22])
            {
                case IDENTITY:
                    printf("[%d] Server: Response Identity!\n",(uint8_t)captured[19]);
                    sendResponseIdentity(handle ,ethhr, captured, info);
                    printf("[%d] Client: Response Identity!\n",(uint8_t)captured[19]);
                    break;
                case NOTIFICATION:
                    printf("[%d] Server: Response Notification!\n",(uint8_t)captured[19]);
                    sendResponseNotify(handle ,ethhr, captured);  //其中进行版本号检测
                    printf("     Client: Response Notification!\n");
                    break;
                case AVAILABLE:
                    printf("[%d] Server: Response Available!\n", (uint8_t)captured[19]);
                    sendResponseIdentity(handle ,ethhr, captured, info);
                    printf("[%d] Client: Response Available!\n", (uint8_t)captured[19]);
                    break;
                case MD5:
                    printf("[%d] Server: Response MD5!\n", (uint8_t)captured[19]);
                    sendResponseMD5(handle, ethhr, captured, info);
                    printf("[%d] Client: Response MD5!\n", (uint8_t)captured[19]);
                default:
                    printf("[%d] Server: (type:%d)!\n",(uint8_t)captured[19],captured[22]);
                    printf("Unexpected packet type!\n");
                    exit(-1);
                    break;
            }
        }
        else if((EAP_TYPE)captured[18] == SUCCESS)
        {
            printf("[%d] Server:Success!\n", (uint8_t)captured[19]);
            system("dhclient eth0");
        }
        else if((EAP_TYPE)captured[18] == FAILURE)
        {
            uint8_t errtype = captured[22];
            uint8_t errsize = captured[23];
            char *msg = (char *)&captured[24];

            printf("[%d] Server: Failure!\n",(uint8_t)captured[19]);
            if(errtype == 0x09 && errsize >0)
            {
                fprintf(stderr,"%s\n",msg);
                exit(-1);
            }
            else if(errtype == 0x08)
            {
                printf("Without Flow!\n");
                exit(-1);
            }
            else
            {
                printf("Error type: 0x%02x\n",errtype);
                exit(-1);
            }
        }
        else
        {
            printf("[%d] Server: (H3C data)\n",(uint8_t)captured[19]);
            pintf("Another packet code!\n");
        }
    }
    return 0;
}


/*獲取mac地址*/
static int GetHostMAC(struct userinfo *info)
{
    int fd;
    struct ifreq req;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd<0)
    {
        perror("socket");
        return 1;
    }
    strcpy(req.ifr_name,info->devname);
    if(ioctl(fd, SIOCGIFHWADDR, &req)<0)
    {
        perror("ioctl");
        return 2;
    }
    memcpy(hostmac,req.ifr_addr.sa_data,6);
    return 0;
}


/*发送EAPoL start包*/
static int PacketStart( pcap_t *handle)
{
    uint8_t packet[18];

    memcpy(packet,DescMAC,6);
    memcpy(packet+6,hostmac,6);

    packet[12] = 0x88;
    packet[13] = 0x8e; 
    packet[14] = 0x01; 
    packet[15] = 0x01; 
    packet[16] = 0x00; 
    packet[17] = 0x00; 

    pcap_sendpacket(handle, packet, sizeof(packet));
}

/*发送通知包*/
static int sendResponseNotify(pcap_t *handle, uint8_t *ethhr, int8_t *captured)
{
    uint8_t packet[67];
    int i = 25;

    assert((EAP_CODE)captured[18] == REQUEST)
    assert((EAP_TYPE)captured[22] == NOTIFICATION)

    memcpy(packet, ether, 14);
    packet[14] = 0x01;
    packet[15] = 0x00;
    packet[16] = 0x00;
    packet[17] = 0x31;

    //49bit长度的packet body
    packet[18] = (EAP_CODE)RESPONSE;
    packet[19] = (uint8_t)captured[19];
    packet[20] = packet[16];
    packet[21] = packet[17];
    packet[22] = (EAP_TPYE)NIOTIFICATION;

    //认证版本加密处理
    //先发送客户端版本
    packet[23] = 0x01;
    packet[24] = 22;//包长
    FillClientVersion(packet+i);//填充加密后的客户端版本号
    i += 20;

    //发送windows版本号
    packet[i++] = 0x02;
    packet[i++] = 22;//包长
    FillWindowsVersion(packet+i);//填充Windows版本号
    i += 20;

    pcap_sendpacket(handle, packet, sizeof(packet));

}


/*发送认证包*/
static int sendResponseIdentity(pcap_t *handle, uint8_t *ethhr, int8_t *captured, struct userinfo *info)
{
    uint8_t response[128];
    size_t i;
    uint16_t indenPackLen;
    uint8_t version[20];
    const char TABLE[] = \
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/"

    assert((EAP_CODE)captured[18] == REQUEST)
    assert((EAP_TYPE)captured[22] == IDENTITY || (EAP_TYPE)captured[22] == AVAILABLE)

    memcpy(response, ethhr, 14);
    packet[14] = 0x01;
    packet[15] = 0x00;
    //packet[16]和packet[17]长度在下面填充


    packet[18] = 0x02;
    packet[19] = (uint8_t)captured[19];
    //packet[20]和packet[21]长度填充,同上

    packet[22] = (((EAP_TYPE)captured[22] == IDENTITY) ? \
            ((EAP_TYPE)IDENTIFY) : ((EAP_TYPE)AVILABLE));

    //填充info->username ,按协议
    if ((EAP_TYPE)captured[22] == IDENTITY)   packet[23] = 0x15;
    if ((EAP_TYPE)captured[22] == AVAILABLE)  packet[23] = 0x00;
    packet[24] = 0x04;
    i = 25;
    memcpy(packet+i,ip,4);
    i += 4;
    packet[i++] = 0x06;
    packet[i++] = 0x07;


    /*填充28位客户端加密版本号*/
    FillClientVersion(version); //获取20位加密版本号
    //按Base64编码转换
    //先三个一组转换
    uint8_t m,n,c1,c2,c3;
    m = 0;n = 0;
    while(m<18)
    {
        c1 = version[m++];
        c2 = version[m++];
        c3 = version[m++];

        packet[i++] = TABLE[ (c1&0xfc)>>2   ]; 
        packet[i++] = TABLE[ ((c2&0xf0)>>4) | ((c1&0x03)<<4) ]; 
        packet[i++] = TABLE[ ((c3&0xc0)>>6) | ((c2&0xf0)<<2) ]; 
        packet[i++] = TABLE[ c3&0x3f ]; 
    }
    //最后处理最后两位
    c1 = version[18];
    c2 = version[19];
    packet[i++] = TABLE[ (c1&0xfc)>>2   ]; 
    packet[i++] = TABLE[ ((c2&0xf0)>>4) | ((c1&0x03)<<4) ]; 
    packet[i++] = TABLE[ (c2&0x0f)<<2 ]; 
    packet[i++] = '='; 
    /*版本号填充结束,继续填充用户名*/


    //i += 28;
    packet[i++] = ' ';
    packet[i++] = ' ';

    int usernamelen;
    usernamelen = strlen(username);
    memcpy(packet+i, info->username, usernamelen);

    i += usernamelen;

    //填充长度
    identPackLen = hons(i-18);
    memcpy(packet+16, &identPackLen, sizeof(identPackLen));
    memcpy(packet+20, &identPackLen, sizeof(identPackLen)); 

    pcap_sendpacket(handle, packet, i);
}


static int FillClientVersion(uint8_t packet[20])//填充加密后的客户端版本号
{
    uint32_t random;
    char randomkey[9];
    char version[16];

    random = (uint32_t) time(NULL);
    sprintf(randomkey, "%08x", random);

    memcpy(packet, H3C_VERSION, 16);
    XOR(packet, 16, randomkey, strlen(randomkey));

    random = htonl(random);
    memcpy(packet+16, &random, 4);

    XOR(packet ,20, H3C_KEY, strlen(H3C_KEY));
}

static int FillWindowsVersion(uint8_t packet[20])//填充Windows版本号
{
    const uint8_t WinVersion[20] = "r70393861";
    memcpy(packet,WinVersion,20);
    XOR(packet,20, H3C_KEY, strlen(H3C_KEY));
    return 1;
}

static int XOR(uint8_t packet[],unsigned int plen ,char H3C_KEY[],unsigned int klen)
{
    int i,j;
    for(i=0;i<plen;i++)
        packet[i] ^= H3C_KEY[i%klen];
    for(i=plen -1,j=0;j<plen;i--;j++)
        packet[i] ^= H3C_KEY[j%klen];
    return 1;
}



static int sendResponseMD5(pcap_t *handle, uint8_t *ethhr,int8_t *captured, struct userinfo *info)
{
    uint8_t response[128];
    uint16_t packetlen;

    assert((EAP_CODE)captured[18] == REQUEST)
    assert((EAP_TYPE)captured[22] == MD5)

    memcpy(response, ether, 14);

    response[14] = 0x01;
    response[15] = 0x00;
    packetlen = htons(22+strlen(info->username));
    memcpy(response+16, packetlen, sizeof(packetlen));

    response[18] = (EAP_CODE)captured[18];
    response[19] = captured[19];
    response[20] = response[16];
    response[21] = response[17];
    response[22] = (EAP_TYPE)captured[22];
    response[23] = 16;

    //6+16位的MD5
    size_t md5len, passwdlen;
    uint8_t md5buf[128];

    md5buf[0] = captured[19];
    passwdlen = strlen(info->passwd);
    memcpy(md5buf+1, info->passwd, passwdlen);
    memcpy(md5buf+passwdlen+1, captured+24, 16);
    md5len = 16 + 1 + passwdlen;
    MD5(md5buf, md5len,response + 24)

    memcpy(response+40, info->username, strlen(info->username));
    pcap_sendpacket(handle , response, sizeof(response));
}
