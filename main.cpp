/*
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 * 
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and 
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 * 
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 * 
 * "sniffer.c" is distributed under these terms:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 * 
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 * 
 ****************************************************************************
 *
 * Below is an excerpt from an email from Guy Harris on the tcpdump-workers
 * mail list when someone asked, "How do I get the length of the TCP
 * payload?" Guy Harris' slightly snipped response (edited by him to
 * speak of the IPv4 header length and TCP data offset without referring
 * to bitfield structure members) is reproduced below:
 * 
 * The Ethernet size is always 14 bytes.
 * 
 * <snip>...</snip>
 *
 * In fact, you *MUST* assume the Ethernet header is 14 bytes, *and*, if 
 * you're using structures, you must use structures where the members 
 * always have the same size on all platforms, because the sizes of the 
 * fields in Ethernet - and IP, and TCP, and... - headers are defined by 
 * the protocol specification, not by the way a particular platform's C 
 * compiler works.)
 *
 * The IP header size, in bytes, is the value of the IP header length,
 * as extracted from the "ip_vhl" field of "struct sniff_ip" with
 * the "IP_HL()" macro, times 4 ("times 4" because it's in units of
 * 4-byte words).  If that value is less than 20 - i.e., if the value
 * extracted with "IP_HL()" is less than 5 - you have a malformed
 * IP datagram.
 *
 * The TCP header size, in bytes, is the value of the TCP data offset,
 * as extracted from the "th_offx2" field of "struct sniff_tcp" with
 * the "TH_OFF()" macro, times 4 (for the same reason - 4-byte words).
 * If that value is less than 20 - i.e., if the value extracted with
 * "TH_OFF()" is less than 5 - you have a malformed TCP segment.
 *
 * So, to find the IP header in an Ethernet packet, look 14 bytes after 
 * the beginning of the packet data.  To find the TCP header, look 
 * "IP_HL(ip)*4" bytes after the beginning of the IP header.  To find the
 * TCP payload, look "TH_OFF(tcp)*4" bytes after the beginning of the TCP
 * header.
 * 
 * To find out how much payload there is:
 *
 * Take the IP *total* length field - "ip_len" in "struct sniff_ip" 
 * - and, first, check whether it's less than "IP_HL(ip)*4" (after
 * you've checked whether "IP_HL(ip)" is >= 5).  If it is, you have
 * a malformed IP datagram.
 *
 * Otherwise, subtract "IP_HL(ip)*4" from it; that gives you the length
 * of the TCP segment, including the TCP header.  If that's less than
 * "TH_OFF(tcp)*4" (after you've checked whether "TH_OFF(tcp)" is >= 5),
 * you have a malformed TCP segment.
 *
 * Otherwise, subtract "TH_OFF(tcp)*4" from it; that gives you the
 * length of the TCP payload.
 *
 * Note that you also need to make sure that you don't go past the end 
 * of the captured data in the packet - you might, for example, have a 
 * 15-byte Ethernet packet that claims to contain an IP datagram, but if 
 * it's 15 bytes, it has only one byte of Ethernet payload, which is too 
 * small for an IP header.  The length of the captured data is given in 
 * the "caplen" field in the "struct pcap_pkthdr"; it might be less than 
 * the length of the packet, if you're capturing with a snapshot length 
 * other than a value >= the maximum packet size.
 * <end of response>
 * 
 ****************************************************************************
 * 
 * Example compiler command-line for GCC:
 *   gcc -Wall -o sniffex sniffex.c -lpcap
 * 
 ****************************************************************************
 *
 * Code Comments
 *
 * This section contains additional information and explanations regarding
 * comments in the source code. It serves as documentaion and rationale
 * for why the code is written as it is without hindering readability, as it
 * might if it were placed along with the actual code inline. References in
 * the code appear as footnote notation (e.g. [1]).
 *
 * 1. Ethernet headers are always exactly 14 bytes, so we define this
 * explicitly with "#define". Since some compilers might pad structures to a
 * multiple of 4 bytes - some versions of GCC for ARM may do this -
 * "sizeof (struct sniff_ethernet)" isn't used.
 * 
 * 2. Check the link-layer type of the device that's being opened to make
 * sure it's Ethernet, since that's all we handle in this example. Other
 * link-layer types may have different length headers (see [1]).
 *
 * 3. This is the filter expression that tells libpcap which packets we're
 * interested in (i.e. which packets to capture). Since this source example
 * focuses on IP and TCP, we use the expression "ip", so we know we'll only
 * encounter IP packets. The capture filter syntax, along with some
 * examples, is documented in the tcpdump man page under "expression."
 * Below are a few simple examples:
 *
 * Expression			Description
 * ----------			-----------
 * ip					Capture all IP packets.
 * tcp					Capture only TCP packets.
 * tcp port 80			Capture only TCP packets with a port equal to 80.
 * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
 *
 ****************************************************************************
 *
 */

#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <boost/program_options.hpp>
#include <boost/format.hpp>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <string.h>

#include "log4cxx/logger.h"
#include "log4cxx/propertyconfigurator.h"
#include "log4cxx/helpers/exception.h"





namespace po = boost::program_options;
namespace bt = boost::posix_time;

using namespace log4cxx;
using namespace log4cxx::helpers;

using boost::asio::ip::tcp;
using boost::asio::ip::udp;

typedef boost::shared_ptr<tcp::socket> socket_ptr;




/*
 * OSI DEFINITIONS AND STRUCTURES
 */

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


/* UDP header */
struct sniff_udp {
  u_short uh_sport;               /* source port */
  u_short uh_dport;               /* destination port */
  u_short uh_ulen;                /* udp length */
  u_short uh_sum;                 /* udp checksum */

};

#define SIZE_UDP        8               /* length of UDP header */


/*
 * GLOBAL VARIABLES
 */
char stringout[1024];

/* logger instance name */
LoggerPtr logger(Logger::getLogger("log1"));

/* boost posix time stamp  */
bt::ptime g_time_now;
bt::ptime g_next_erase_status_time;
bt::ptime g_next_write_time;
bt::ptime g_next_read_time;

/* event vector for reporting */
std::vector<std::string> g_event_vector;
double gCurrentTxFrequency;
double gCurrentTxSampleRate;
double gLowerTxFreqBound;
double gUpperTxFreqBound;

#define INITIALIZE_EVENT_PARAMETERS		\
	g_event_vector.resize(0);		\
	gCurrentTxFrequency = 0.0;		\
	gCurrentTxSampleRate = 0.0;		\
	gLowerTxFreqBound = 9900e6;		\
	gUpperTxFreqBound = 0.0;


/* report thread counter */
int n_rpt_thread_cnt = 0;
int n_control_thread_cnt = 0;

/*
 * DEFINE FUNCTION PROTOTYPES
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset);

void print_app_banner(void);

/*
 * app name/banner
 */
void print_app_banner(void)
{

	fprintf(stderr,"%s - %s\n", APP_NAME, APP_DESC);
	fprintf(stderr,"%s\n", APP_COPYRIGHT);
	fprintf(stderr,"%s\n", APP_DISCLAIMER);
	fprintf(stderr,"\n");

return;
}


/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	fprintf(stderr,"%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		fprintf(stderr,"%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			fprintf(stderr," ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		fprintf(stderr," ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			fprintf(stderr,"   ");
		}
	}
	fprintf(stderr,"   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			fprintf(stderr,"%c", *ch);
		else
			fprintf(stderr,".");
		ch++;
	}

	fprintf(stderr,"\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;            /* The UDP header */
	const u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	static u_short _R = 0, _T = 0, _D = 0, _MOD = 0, _FRAC = 0, _INT = 0;
	static u_short _SEQ_STATE = 0x0000;
	static u_short _print_udp_payload = 0;
	
	//fprintf(stderr,"\nPacket number %d:", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		fprintf(stderr,"   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	//fprintf(stderr,"       From: %s", inet_ntoa(ip->ip_src));
	//fprintf(stderr,"         To: %s\n", inet_ntoa(ip->ip_dst));
	
	/* determine protocol */	
	switch(ip->ip_p)
	{
	  case IPPROTO_TCP:
	    fprintf(stderr,"   Protocol: TCP\n");
	    /*
	     *  OK, this packet is TCP.
	     */
	    
	    /* define/compute tcp header offset */
	    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	    size_tcp = TH_OFF(tcp)*4;
	    if (size_tcp < 20) {
	      fprintf(stderr,"   * Invalid TCP header length: %u bytes\n", size_tcp);
	      return;
	    }
	    
	    fprintf(stderr,"   Src port: %d\n", ntohs(tcp->th_sport));
	    fprintf(stderr,"   Dst port: %d\n", ntohs(tcp->th_dport));
	    
	    /* define/compute tcp payload (segment) offset */
	    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	    //payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	    
	    /* compute tcp payload (segment) size */
	    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	    
	    /*
	     * Print payload data; it might be binary, so don't just
	     * treat it as a string.
	     */
#if 0
	    if (size_payload > 0) {
	      fprintf(stderr,"   Payload (%d bytes):\n", size_payload);
	      print_payload(payload, size_payload);
	    }
#endif	    
	    break;

	  case IPPROTO_UDP:
            //fprintf(stderr,"   Protocol: UDP");
            /*
             *  OK, this packet is UDP.
             */

            /* define/compute tcp header offset */
            udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

            //fprintf(stderr,"   Src port: %d", ntohs(udp->uh_sport));
            //fprintf(stderr,"   Dst port: %d\n", ntohs(udp->uh_dport));

	    /* define/compute udp payload (segment) offset */
	    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_UDP);

	    
	    /* compute udp payload (segment) size */
	    size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
	    if (size_payload > ntohs(udp->uh_ulen))
	      size_payload = ntohs(udp->uh_ulen);
	    
	    /* NP
	     * Check for tx set rate command
	     */
	    if ( ntohs(udp->uh_dport) == 49159)
	    {
	      if (payload[11] == 0xa2)
		{
		  u_char hb_div = 1; 
		  u_int uw32 = *((u_int*)&payload[12]);
		  uw32 = ntohl(uw32);
		  u_char div = payload[15];
		  hb_div *= (payload[14] & 0x1) ? 2 : 1;
		  hb_div *= (payload[14] & 0x2) ? 2 : 1;
		  div *= hb_div;
		  double tx_rate = 100e6 / (double)(div);

		  sprintf(stringout,"[UHD txrate] uw32 = 0x%x, hb_div = %i, tx_rate = %14.10e", uw32, hb_div, tx_rate);
		  LOG4CXX_TRACE(logger,stringout);

		  // record set tx sample rate change
		  //    may affect performace during high event rate.
		  g_time_now = bt::microsec_clock::local_time();
		  std::string event_string;
		  event_string  = bt::to_simple_string(g_time_now) + " | ";
		  event_string += " txrate | ";
		  event_string += boost::lexical_cast<std::string>(tx_rate) + "\n";
	      
		  g_event_vector.push_back(event_string);

		  sprintf(stringout,"[UHD txrate] tx rate = %10.3f Msps", tx_rate / 1e6);
		  LOG4CXX_INFO(logger,stringout);
		  gCurrentTxSampleRate = tx_rate;

		  // THIS SHOULD GO SOMEWHERE ELSE
		  // Calculate Upper and lower bounds for Tx Spectrum 
		  //double lowbound   = gCurrentTxFrequency - (gCurrentTxSampleRate / 2.0);
		  //double upperbound = gCurrentTxFrequency + (gCurrentTxSampleRate / 2.0);
	    
		  gLowerTxFreqBound = std::min(gCurrentTxFrequency - (gCurrentTxSampleRate / 2.0),   gLowerTxFreqBound);
		  gUpperTxFreqBound = std::max(gCurrentTxFrequency + (gCurrentTxSampleRate / 2.0),   gUpperTxFreqBound);

		  _print_udp_payload = 1;
		}

	      /* NP
	       * Check for tx set freq comand. Start sequence for SPI commands to follow.
	       */
	      if ((payload[11] == 0x15) && (payload[12] == 0x60) && (payload[15] == 0x80))
		{
		  _SEQ_STATE = (0x1 << 0);
		  _print_udp_payload = 1;
		}

	      if ((payload[11] == 0x16) && ((payload[15] & 0x7) == 0) && (_SEQ_STATE))
		{
		  u_int uw32 = *((u_int*)&payload[12]);
		  uw32 = ntohl(uw32);
		  _FRAC = (uw32 >>  3) & 0x0fff;
		  _INT = (uw32 >> 15) & 0xffff;

		  sprintf(stringout,"[UHD txfreq] uw32 = 0x%x        FRAC = %d      INT = %d", uw32, _FRAC, _INT);
		  LOG4CXX_TRACE(logger,stringout);

		  _SEQ_STATE |= (0x1 << 1);
		  _print_udp_payload = 1;
		}
	      else if ((payload[11] == 0x16) && ((payload[15] & 0x7) == 1) && (_SEQ_STATE))
		{
		  u_int uw32 = *((u_int*)&payload[12]);
		  uw32 = ntohl(uw32);
		  _MOD = (uw32 >>  3) & 0x0fff;

		  sprintf(stringout,"[UHD txfreq] uw32 = 0x%x        MOD = %d", uw32, _MOD);
		  LOG4CXX_TRACE(logger,stringout);

		  _SEQ_STATE |= (0x1 << 2);
		  _print_udp_payload = 1;
		}
	      else if ((payload[11] == 0x16) && ((payload[15] & 0x7) == 2) && (_SEQ_STATE))
		{
		  u_int uw32 = *((u_int*)&payload[12]);
		  uw32 = ntohl(uw32);
		  _R = (uw32 >> 14) & 0x03ff;
		  _T = (uw32 >> 24) & 0x0001;
		  _D = (uw32 >> 25) & 0x0001;

		  sprintf(stringout,"[UHD txfreq] uw32 = 0x%x        R = %d    T = %d    D = %d", uw32, _R, _T, _D);
		  LOG4CXX_TRACE(logger,stringout);

		  _SEQ_STATE |= (0x1 << 3);

		  _print_udp_payload = 1;
		}

	      if (_SEQ_STATE == 0x000f)
		{
		  double fpd;
		  fpd = (float)100e6 * ( (float)(1.0+(float)_D)/(float)((float)_R*(1.0+(float)_T)) );
		  //fpd = 1.0 + _D;
		  //fpd = fpd / (float)_R;
		  double rfant = fpd * ((float)_INT + (float)_FRAC/(float)_MOD ); 

		  sprintf(stringout,"[UHD txfreq] fpd = %f    rfant = %14.10e", fpd, rfant);
		  LOG4CXX_TRACE(logger,stringout);

		  // record set tx frequency change
		  //    may affect performace during high event rate.
		  g_time_now = bt::microsec_clock::local_time();
		  std::string event_string;
		  event_string  = bt::to_simple_string(g_time_now) + " | ";
		  event_string += " txfreq | ";
		  event_string += boost::lexical_cast<std::string>(rfant) + "\n";
	      
		  g_event_vector.push_back(event_string);

		  sprintf(stringout,"[UHD txfreq] tx freq = %10.2f MHz", rfant / 1e6);
		  LOG4CXX_INFO(logger,stringout);
		  gCurrentTxFrequency = rfant;

		  // THIS SHOULD GO SOMEWHERE ELSE
		  // Calculate Upper and lower bounds for Tx Spectrum 
		  //double lowbound   = gCurrentTxFrequency - (gCurrentTxSampleRate / 2.0);
		  //double upperbound = gCurrentTxFrequency + (gCurrentTxSampleRate / 2.0);
	    
		  gLowerTxFreqBound = std::min(gCurrentTxFrequency - (gCurrentTxSampleRate / 2.0),   gLowerTxFreqBound);
		  gUpperTxFreqBound = std::max(gCurrentTxFrequency + (gCurrentTxSampleRate / 2.0),   gUpperTxFreqBound);
	      
		  // reset _SEQ_STATE
		  _SEQ_STATE = 0x0000;
		}

	      /*
	       * Print payload data; it might be binary, so don't just
	       * treat it as a string.
	       */
	      if ((size_payload > 0) && (_print_udp_payload == 10))
		{
		  fprintf(stderr,"   Payload (%d bytes):\n", size_payload);
		  print_payload(payload, size_payload);

		  _print_udp_payload = 0;
		}
	    } // if ( ntohs(udp->uh_dport) == 49159)

	    else if ( ntohs(udp->uh_dport) == 49154) // the payload[7] values correspond to typedefs in usrp_simple_burner_utils.hpp (not included here)
	    {
	      //print_payload(payload, size_payload);
	      if (payload[7] == 'f')
	      {
		sprintf(stringout,"[UHD flash] request for flash info");
		LOG4CXX_INFO(logger,stringout);
	      }
	      else if (payload[7] == 'e')
	      {
		sprintf(stringout,"[UHD flash] request for erase");
		LOG4CXX_INFO(logger,stringout);
	      }
	      else if (payload[7] == 'd')
	      {
		if (bt::microsec_clock::local_time() > g_next_erase_status_time)
		{
		  sprintf(stringout,"[UHD flash] request for erase status");
		  LOG4CXX_INFO(logger,stringout);
		  g_next_erase_status_time = bt::microsec_clock::local_time() + bt::milliseconds(1000);
		}
	      }
	      else if (payload[7] == 'w')
	      {
		if (bt::microsec_clock::local_time() > g_next_write_time)
		{
		  sprintf(stringout,"[UHD flash] request for write");
		  LOG4CXX_INFO(logger,stringout);
		  g_next_write_time = bt::microsec_clock::local_time() + bt::milliseconds(1000);
		}
	      }
	      else if (payload[7] == 'r')
	      {
                if (bt::microsec_clock::local_time() > g_next_read_time)
		{
		  sprintf(stringout,"[UHD flash] request for read");
		  LOG4CXX_INFO(logger,stringout);
		  g_next_read_time = bt::microsec_clock::local_time() + bt::milliseconds(1000);
		}
	      }
	      else if (payload[7] == 's')
	      {
		sprintf(stringout,"[UHD flash] request for reset");
		LOG4CXX_INFO(logger,stringout);
	      }

	    }// if ( ntohs(udp->uh_dport) == 49154)

	    return;
	  case IPPROTO_ICMP:
	    fprintf(stderr,"   Protocol: ICMP\n");
	    return;
	  case IPPROTO_IP:
	    fprintf(stderr,"   Protocol: IP\n");
	    return;
	  default:
	    fprintf(stderr,"   Protocol: unknown\n");
	    return;
	} // End of switch
	
	return;
}



void report_session(socket_ptr sock)
{
  // REMOVE VARIABLE NOT USED
  char data[100];
  char* temp_str;
  char* argv[20];
  int argc = 0, data_len;
  boost::system::error_code error;
  std::string command, mode;

  //setup the program options
  po::options_description desc("Allowed options");
  desc.add_options()
    ("command", po::value<std::string>(&command), "prepare or start command")
    ("mode", po::value<std::string>(&mode)->default_value("BIN"), "Select mode")
    ;

  //po::variables_map vm;

  try
  { 
    while(1)
    {
      data_len = sock->read_some(boost::asio::buffer( data ), error); // wait for the client to query
      if(error == boost::asio::error::eof)
      {
        LOG4CXX_INFO(logger, "Connection closed");
        break;
      }
      else if(error)
        throw boost::system::system_error(error);

      // parse the incoming command
      argc = 0;
      argv[0] = (char *)"temp";
      data[data_len] = '\0';
      temp_str = strtok(data, " ");
      while(temp_str != NULL)
      {
	argc++;
	argv[argc] = temp_str;
	temp_str = strtok(NULL, " ");
      }
      argc++;

      LOG4CXX_INFO(logger, "argc " << argc << " argv[1] " << argv[1] <<  " argv[2] " << argv[2]);
      po::variables_map vm;
      po::store(po::parse_command_line(argc, argv, desc), vm);
      po::notify(vm);

      LOG4CXX_INFO(logger, "Command: " << command);

      std::string resp;
      if (command.compare("bw") == 0)
      {
	std::ostringstream ssresp;
	ssresp << "spectrum usage (MHz)," ;
	ssresp << std::fixed << std::setprecision(2) << gLowerTxFreqBound / 1e6;
	ssresp << "," ;
	ssresp << std::fixed << std::setprecision(2) << gUpperTxFreqBound / 1e6;
	ssresp << "\n";
	resp = ssresp.str();
	LOG4CXX_INFO(logger, resp);
      }
      else if (command.compare("history") == 0)
      {
	if (g_event_vector.size() == 0)
	  resp += "No entry\n";
	else
	{
	  //for (u_int i = g_event_vector.size()-1; i > 0 ; --i)  // reverse order
	  for (u_int i = 0; i < g_event_vector.size()-1 ; ++i)
	    resp += g_event_vector.at(i);
	}
	LOG4CXX_INFO(logger, resp);
      }
      else
      {
	resp = "command unknown\n";
	LOG4CXX_INFO(logger, resp);
      }

      boost::asio::write(*sock, boost::asio::buffer(resp.data(),resp.size() ));

    }
    LOG4CXX_INFO(logger, "Report thread count: " << --n_rpt_thread_cnt << " [host: " << sock->remote_endpoint().address().to_string() << "]" );
  }  
  catch (std::exception& e)
  {
    std::cerr << "Exception in report thread: " << e.what() << "\n";
    LOG4CXX_ERROR(logger, "report thread count: " << --n_rpt_thread_cnt << " [host: " << sock->remote_endpoint().address().to_string() << "]" );
    return;
  }
}

void report_server(short port)
{
  boost::asio::io_service io_service;

  LOG4CXX_INFO(logger, "Starting report server at " << port);
  tcp::acceptor a(io_service, tcp::endpoint(tcp::v4(), port));
  for (;;)
  {
    socket_ptr sock(new tcp::socket(io_service));
    if (n_rpt_thread_cnt >= 1) continue;
    a.accept(*sock);
    boost::thread t(boost::bind(report_session, sock));
    LOG4CXX_INFO(logger, "Report thread count: " << ++n_rpt_thread_cnt << " [host: " << sock->remote_endpoint().address().to_string() << "]" );
  }
}

#if 1
void control_session(socket_ptr sock)
{
  // REMOVE VARIABLE NOT USED
  char data[100];
  char* temp_str;
  char* argv[20];
  int argc = 0, data_len;
  boost::system::error_code error;
  std::string command, mode;

  //setup the program options
  po::options_description desc("Allowed options");
  desc.add_options()
    ("command", po::value<std::string>(&command), "prepare or start command")
    ("mode", po::value<std::string>(&mode)->default_value("BIN"), "Select mode")
    ;

  //po::variables_map vm;

  try
  { 
    while(1)
    {
      data_len = sock->read_some(boost::asio::buffer( data ), error); // wait for the client to query
      if(error == boost::asio::error::eof)
      {
        LOG4CXX_INFO(logger, "Connection closed");
        break;
      }
      else if(error)
        throw boost::system::system_error(error);

      // parse the incoming command
      argc = 0;
      argv[0] = (char *)"temp";
      data[data_len] = '\0';
      temp_str = strtok(data, " ");
      while(temp_str != NULL)
      {
	argc++;
	argv[argc] = temp_str;
	temp_str = strtok(NULL, " ");
      }
      argc++;

      LOG4CXX_INFO(logger, "argc " << argc << " argv[1] " << argv[1] <<  " argv[2] " << argv[2]);
      po::variables_map vm;
      po::store(po::parse_command_line(argc, argv, desc), vm);
      po::notify(vm);

      LOG4CXX_INFO(logger, "Command: " << command);

      std::string resp;
      if (command.compare("start") == 0)
      {

	INITIALIZE_EVENT_PARAMETERS;

	resp = "Start command received";
	LOG4CXX_INFO(logger, resp);
      }
      else
      {
	resp = "command unknown\n";
	LOG4CXX_INFO(logger, resp);
      }

      //boost::asio::write(*sock, boost::asio::buffer(resp.data(),resp.size() ));

    }
    LOG4CXX_INFO(logger, "Control thread count: " << --n_control_thread_cnt << " [host: " << sock->remote_endpoint().address().to_string() << "]" );
  }  
  catch (std::exception& e)
  {
    std::cerr << "Exception in Control thread: " << e.what() << "\n";
    LOG4CXX_ERROR(logger, "control thread count: " << --n_control_thread_cnt << " [host: " << sock->remote_endpoint().address().to_string() << "]" );
    return;
  }
}

void control_server(short port)
{
  boost::asio::io_service io_service;

  LOG4CXX_INFO(logger, "Starting control server at " << port);
  tcp::acceptor a(io_service, tcp::endpoint(tcp::v4(), port));
  for (;;)
  {
    socket_ptr sock(new tcp::socket(io_service));
    if (n_control_thread_cnt >= 1) continue;
    a.accept(*sock);
    boost::thread t(boost::bind(control_session, sock));
    LOG4CXX_INFO(logger, "Control thread count: " << ++n_control_thread_cnt << " [host: " << sock->remote_endpoint().address().to_string() << "]" );
  }
}
#endif

int main(int argc, char **argv)
{

  char *dev = NULL;			/* capture device name */
  char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
  pcap_t *handle;				/* packet capture handle */

  //NPchar filter_exp[] = "ip";		/* filter expression [3] */
  //char filter_exp[] = "icmp";		/* filter expression [3] */
  char *filter_exp = NULL;		/* filter expression [3] */


  struct bpf_program fp;			/* compiled filter program (expression) */
  bpf_u_int32 mask;			/* subnet mask */
  bpf_u_int32 net;			/* ip */
  int num_packets;			/* number of packets to capture */

  std::string interface;
  std::string filter;
  int base_port_number,report_server_port, control_server_port;


  INITIALIZE_EVENT_PARAMETERS;

  g_next_write_time = g_next_read_time = g_next_erase_status_time = bt::microsec_clock::local_time();

  print_app_banner();

  // Configure the logger
  PropertyConfigurator::configure("/root/SNIFFEX/logconf.prop");

  // SETUP THE PROGRAM OPTIONS
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help",    "brief description of get/set handlers")
    ("intf",    po::value<std::string>(&interface)->default_value("eth0"), "Interface to sniff")
    ("filter",  po::value<std::string>(&filter)->default_value("udp and (port 49159 or port 49154)"),    "Filter expression for BPF")
    ("packets", po::value<int>(&num_packets)->default_value(-1), "Number of packets")
    ("port", po::value<int>(&base_port_number)->default_value(6100), "Specify port number")
    ;

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  // PRINT THE HELP MESSAGE AND CHECK FOR REQUIRED OPTIONS
  if (vm.count("help")){
    std::cerr << boost::format("%s") % desc << std::endl;
    return ~0;
  }
  else if (not vm.count("intf")){
    std::cerr << "Must specify interface with --intf" << std::endl;
    return ~0;
  }
  else if (not vm.count("filter")){
    std::cerr << "Must specify interface with --filter" << std::endl;
    return ~0;
  }


  /* START CONTROL THREAD */ 
  control_server_port = base_port_number + 1;
  boost::thread control_thread(control_server, control_server_port);
  LOG4CXX_INFO(logger,"Control server started on port " << control_server_port);

  /* START REPORTING THREAD*/
  report_server_port = base_port_number + 0;
  boost::thread rpt_thread(report_server, report_server_port);
  LOG4CXX_INFO(logger,"Report server started on port " << report_server_port);

  /* SET UP SNIFFER */

  dev = (char *)interface.c_str();
  filter_exp = (char *)filter.c_str();

	
  /* get network number and mask associated with capture device */
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    LOG4CXX_WARN(logger, "Couldn't get netmask for device " << dev << ": " << errbuf);
    net = 0;
    mask = 0;
  }

  /* print capture info */
  LOG4CXX_INFO(logger,"Device: " << dev);
  LOG4CXX_INFO(logger,"Number of packets: " << num_packets);
  LOG4CXX_INFO(logger,"Filter expression: " << filter_exp);
  
  /* open capture device */
  handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
  if (handle == NULL)
  {
    sprintf(stringout, "Couldn't open device %s: %s", dev, errbuf);
    LOG4CXX_ERROR(logger, stringout);
    exit(EXIT_FAILURE);
  }

  /* make sure we're capturing on an Ethernet device [2] */
  if (pcap_datalink(handle) != DLT_EN10MB) {
    sprintf(stringout, "%s is not an Ethernet device", dev);
    LOG4CXX_ERROR(logger, stringout);
    exit(EXIT_FAILURE);
  }

  /* compile the filter expression */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    sprintf(stringout, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    LOG4CXX_ERROR(logger, stringout);
    exit(EXIT_FAILURE);
  }

  /* apply the compiled filter */
  if (pcap_setfilter(handle, &fp) == -1) {
    sprintf(stringout, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    LOG4CXX_ERROR(logger, stringout);
    exit(EXIT_FAILURE);
  }

  /* now we can set our callback function */
  if ( pcap_loop(handle, num_packets, got_packet, NULL) == -1) {
    sprintf(stringout, "pcap_loop error: %s\n", pcap_geterr(handle));
    LOG4CXX_ERROR(logger, stringout);
    exit(EXIT_FAILURE);
  }

  /* cleanup */
  pcap_freecode(&fp);
  pcap_close(handle);
  
  sprintf(stringout, "Capture complete: %i packets.\n", num_packets);
  LOG4CXX_INFO(logger, stringout);

  return 0;
}

