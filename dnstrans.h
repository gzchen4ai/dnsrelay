#ifndef DNSTRANS_H
#define DNSTRANS_H

#include <stdio.h>
#include <string.h>
#include <WinSock2.h>

#pragma comment (lib, "Ws2_32.lib")

#define MAX_BUFLEN 512
//#define _CRT_SECURE_NO_WARNINGS 

typedef _Bool bool;

typedef struct
{
	unsigned short id;
	bool qr;
	unsigned char opcode;
	bool aa;
	bool tc;
	bool rd;
	bool ra;
	unsigned char z;
	unsigned char rcode;
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
}DNSHeader;

typedef struct
{
	char* qname;
	unsigned short qtype;
	unsigned short qclass;
}DNSQuery;

typedef struct
{
	char* qname;
	unsigned short rtype;
	unsigned short rclass;
	unsigned int ttl;
	unsigned short rdlength;
	unsigned short pref;
	char* rdata;
}DNSRecord;

typedef struct
{
	DNSRecord *record;
	int len;
}DNSRecords;

typedef DNSRecords* pDNSRecords; 

typedef struct
{
	DNSHeader* header;
	DNSQuery* qptr[128];
	DNSRecord* rptr[128];
}DNSPacket;

typedef DNSPacket* pDNSPacket; 

/*
DNSHeader* toDNSHeader(char* src, char** retPtr);
char* fromDNSHeader(DNSHeader* headerPtr, int* len);
DNSName* toDNSName(char* src, char* st, char** retPtr);
char* fromDNSName(DNSName* namePtr, int* len);
DNSQuery* toDNSQuery(char* src, char* st, char** retPtr);
char* fromDNSQuery(DNSQuery* queryPtr, int* len);
DNSRecord* toDNSRecord(char* src, char* st, char** retPtr);
char* fromDNSRecord(DNSRecord * recordPtr, int* len);
DNSPacket* toDNSPacket(char* src);
char* fromDNSPacket(DNSPacket* packetPtr, int* len);
*/

/*
* Convert char[] to DNSHeader, returns the pointer of DNSHeader
* Length: 12 bytes
*/
void toDNSHeader(DNSHeader* retp,char* src, char** retPtr)
{
	unsigned short* ptr = (unsigned short*)src;
	unsigned short word;

	word = ntohs(*ptr);
	retp->id = word;

	++ptr;
	word = ntohs(*ptr);
	retp->qr = (bool)((word & 0x8000) >> 15);
	retp->opcode = (unsigned char)((word & 0x7800) >> 11);
	retp->aa = (bool)((word & 0x0400) >> 10);
	retp->tc = (bool)((word & 0x0200) >> 9);
	retp->rd = (bool)((word & 0x0100) >> 8);
	retp->ra = (bool)((word & 0x0080) >> 7);
	retp->z = (unsigned char)((word & 0x0070) >> 4);
	retp->rcode = (unsigned char)(word & 0x000f);

	++ptr;
	word = ntohs(*ptr);
	retp->qdcount = word;

	++ptr;
	word = ntohs(*ptr);
	retp->ancount = word;

	++ptr;
	word = ntohs(*ptr);
	retp->nscount = word;

	++ptr;
	word = ntohs(*ptr);
	retp->arcount = word;
	
	++ptr;
	
	*retPtr = (char*)ptr;
}

/*
* Convert DNSHeader to char[], returns the pointer of char[]
* 13 bytes, '\0' for the last byte
*/
char* fromDNSHeader(DNSHeader* headerPtr, int* len)
{
	char* retp = (char*)malloc(13 * sizeof(char));
	unsigned short* p = (unsigned short*)retp;
	unsigned short word;
	
	*(p++) = htons(headerPtr->id);

	word = headerPtr->qr << 15;
	word |= headerPtr->opcode << 11;
	word |= headerPtr->aa << 10;
	word |= headerPtr->tc << 9;
	word |= headerPtr->rd << 8;
	word |= headerPtr->ra << 7;
	word |= headerPtr->z << 4;
	word |= headerPtr->rcode;
	*(p++) = htons(word);
	
	*(p++) = htons(headerPtr->qdcount);
	*(p++) = htons(headerPtr->ancount);
	*(p++) = htons(headerPtr->nscount);
	*(p++) = htons(headerPtr->arcount);

	*(char*)p = 0;
	*len = 12;
	return retp;
}

/*
* Convert NAME field to DNSname, which format is like "www.baidu.com" 
* Due to usage of Message Compression, we cannot decide the length of NAME field in advance,
* so we will simply allocate MAX_BUFLEN bytes
*/
void toDNSName(char* retp,char* src, char* st, char** retPtr)
{
	int i, tmp, jump = 0, fir = 1;
	char* dst = retp;
	unsigned char* cptr;
	
	cptr = (unsigned char*)src;
	while (1)
	{
		tmp = *cptr;
		if (tmp == 0)
			break;
		if (tmp < 192)
		{
			cptr++;
			if (!fir)
				*(dst++) = '.';
			else
				fir = 0;
			for (i = 0; i < tmp; i++, cptr++)
			{
				*(dst++) = *cptr;
			}
		}
		else
		{
			if (!jump)
				*retPtr = (char*)(cptr + 2);
			jump = 1;
			cptr = (unsigned char*)(st + (ntohs(*((unsigned short*)cptr)) - 49152));
		}
	}
	*dst=0;

	if (!jump)
		*retPtr = (char*)(cptr + 1);
}

/*
* Convert DNSName to NAMEFIELD, which format is like "3www5baidu3com0"
* length will increase by 1, add 1 bytes for '\0'
*/
char* fromDNSName(char* namePtr, int* len)
{
	int length = strlen(namePtr), cnt=0, i;
	char* ret = (char*)malloc((length + 2) * sizeof(char));
	char* dstPtr = ret, * srcPtr = namePtr;

	for (i = 0; i < length; i++)
	{
		if (namePtr[i] != '.')
		{
			++cnt;
		}
		else
		{
			*(dstPtr++) = (char)cnt;
			while (cnt--)
			{
				*(dstPtr++) = *(srcPtr++);
			}
			cnt = 0;
			srcPtr++;
		}
	}
	if(cnt>0)
	{
		*(dstPtr++) = (char)cnt;
		while(cnt--)
			*(dstPtr++) = *(srcPtr++);
	}
	*dstPtr = 0;

	*len = length + 2;
	return ret;
}

/*
* Convert char[] to DNSQuery
* QNAME filed:
*	note that QNAME filed may be an odd number of octets, no padding is used
*	no Message Compression
* 
*/
void toDNSQuery(DNSQuery* retp,char* src, char* st, char** retPtr)
{
	char* cptr = src;
	
	/*
	int length = 0;
	while (*(cptr + length) != 0)
		length++;
	char* str = (char*)malloc((length + 1) * sizeof(char)); // add 1 bytes for '\0'
	strcpy(str, src);
	retp->qname = str;
	
	unsigned short* sptr = (unsigned short*)(src + length + 1);
	*/
	retp->qname = (char*)malloc(MAX_BUFLEN * sizeof(char));
	toDNSName(retp->qname, src, st, &cptr);

	unsigned short* sptr = (unsigned short*)cptr;
	retp->qtype = ntohs(*(sptr++));
	retp->qclass = ntohs(*(sptr++));
	
	*retPtr = (char*)sptr;
}

/*
* Convert DNSQuery to char[]
* note that the last byte of QNAME field is '\0'
* note to free the return pointer
*/

char* fromDNSQuery(DNSQuery* queryPtr, int* len)
{
	int length = strlen(queryPtr->qname), t;
	char* ret = (char*)malloc((length + 6) * sizeof(char));
	
	char* nameStr = fromDNSName(queryPtr->qname, &t);
	memcpy(ret, nameStr, t * sizeof(char));
	free(nameStr);
	
	unsigned short* sptr = (unsigned short*)(ret + t);
	*(sptr++) = htons(queryPtr->qtype);
	*(sptr++) = htons(queryPtr->qclass);

	*len = length + 6;
	return ret;
}

/*
* Convert char[] to DNSRecord
* 
*/

void toDNSRecord(DNSRecord* retp, char* src, char* st, char** retPtr)
{
	char* cptr = src;

	/*
	int length = 0;
	while (*(cptr + length) != 0)
		length++;
	char* str = (char*)malloc((length + 1) * sizeof(char)); // add 1 bytes for '\0'
	strcpy(str, src);
	retp->qname = str;
	
	unsigned short* sptr = (unsigned short*)(src + length + 1);
	*/
	retp->qname = (char*)malloc(MAX_BUFLEN * sizeof(char));
	toDNSName(retp->qname, src, st, &cptr);
	
	unsigned short* sptr = (unsigned short*)cptr;
	retp->rtype = ntohs(*(sptr++));
	retp->rclass = ntohs(*(sptr++));
	retp->ttl = ntohl(*((int*)sptr));
	sptr += 2;
	retp->rdlength = ntohs(*(sptr++));
	retp->pref = 0;

	cptr = (char*)sptr;
	if (retp->rtype == 1 || retp->rtype == 28) /* A or AAAA */
	{
		char* str = (char*)malloc((retp->rdlength + 1) * sizeof(char)); /* add 1 bytes for '\0' */
		memcpy(str, cptr, retp->rdlength*sizeof(char));
		str[retp->rdlength] = 0;
		retp->rdata = str;

		*retPtr = (char*)sptr + retp->rdlength;
	}
	else if (retp->rtype == 5) /* CNAME */
	{
		retp->rdata = (char*)malloc(MAX_BUFLEN * sizeof(char));
		toDNSName(retp->rdata, cptr, st, &cptr);
		
		retp->rdlength = strlen(retp->rdata) + 2;

		*retPtr = cptr;
	}
	else if (retp->rtype == 15) /* MX */
	{
		retp->pref = ntohs(*(sptr++));
		cptr = (char*)sptr;
		retp->rdata = (char*)malloc(MAX_BUFLEN * sizeof(char));
		toDNSName(retp->rdata, cptr, st, &cptr);

		retp->rdlength = strlen(retp->rdata) + 4;

		*retPtr = cptr;
	}
}

/*
* Convert DNSRecord to char[]
* note to free the return pointer
*/
char* fromDNSRecord(DNSRecord* recordPtr, int* len)
{
	/* increased by 1 bytes, add 2 bytes for two '\0' */
	int length = strlen(recordPtr->qname) + 13, t;
	char* ret = (char*)malloc(MAX_BUFLEN * sizeof(char));

	char* nameStr = fromDNSName(recordPtr->qname, &t);
	memcpy(ret, nameStr, t*sizeof(char));
	free(nameStr);

	char* cptr = ret + t;
	unsigned short* sptr = (unsigned short*)cptr;

	*(sptr++) = htons(recordPtr->rtype);
	*(sptr++) = htons(recordPtr->rclass);
	*(int*)(sptr) = htonl(recordPtr->ttl);
	sptr += 2;
	*(sptr++) = htons(recordPtr->rdlength);
	
	if (recordPtr->rtype == 1 || recordPtr->rtype == 28) /* A or AAAA */
	{
		cptr = (char*)sptr;
		memcpy(cptr, recordPtr->rdata, recordPtr->rdlength*sizeof(char));
		cptr[recordPtr->rdlength] = 0;
		length += recordPtr->rdlength;
	}
	else if (recordPtr->rtype == 5) /* CNAME */
	{
		cptr = (char*)sptr;
		nameStr = fromDNSName(recordPtr->rdata, &t);
		memcpy(cptr, nameStr, t*sizeof(char));
		free(nameStr);
		length += t;
	}
	else if (recordPtr->rtype == 15) /* MX */
	{
		*(sptr++) = htons(recordPtr->pref);
		cptr = (char*)sptr;
		nameStr = fromDNSName(recordPtr->rdata, &t);
		memcpy(cptr, nameStr, t*sizeof(char));
		free(nameStr);
		length += 2 + t;
	}

	*len = length - 1;
	return ret;
}

/*
* Convert char[] to DNSPacket
* 
*/
void toDNSPacket(DNSPacket* retp,char* src)
{
	int i;
	char* cur=src;
	
	retp->header = (DNSHeader*)malloc(sizeof(DNSHeader));
	toDNSHeader(retp->header, cur, &cur);
	
	for (i = 0; i < (retp->header->qdcount); i++)
	{
		retp->qptr[i] = (DNSQuery*)malloc(sizeof(DNSQuery));
		toDNSQuery(retp->qptr[i], cur, src, &cur);
	}
	for (i = 0; i < (retp->header->ancount); i++)
	{
		retp->rptr[i] = (DNSRecord*)malloc(sizeof(DNSRecord));
		toDNSRecord(retp->rptr[i], cur, src, &cur);
	}
}

/*
* Convert DNSPacket to char[]
* note to free the return pointer
*/
char* fromDNSPacket(DNSPacket* packetPtr, int* len)
{
	char* ret = (char*)malloc(MAX_BUFLEN * sizeof(char));
	char* tmp;
	char* cur = ret;
	int length, i;
	*len=0;
	
	tmp = fromDNSHeader(packetPtr->header, &length);
	memcpy(cur, tmp, length*sizeof(char));
	cur += length;
	*len += length;
	free(tmp);

	for (i = 0; i < (packetPtr->header->qdcount); i++)
	{
		tmp = fromDNSQuery(packetPtr->qptr[i], &length);
		memcpy(cur, tmp, length*sizeof(char));
		cur += length;
		*len += length;
		free(tmp);
	}

	for (i = 0; i < (packetPtr->header->ancount); i++)
	{
		tmp = fromDNSRecord(packetPtr->rptr[i], &length);
		memcpy(cur, tmp, length*sizeof(char));
		cur += length;
		*len += length;
		free(tmp);
	}

	return ret;
}

/*
* Append DNSRecords to DNSPacket
*/
void appendDNSRecords(DNSPacket* packetPtr, DNSRecords* recordsPtr)
{
	int i;

	packetPtr->header->qr = 1;
	packetPtr->header->ancount = recordsPtr->len;

	for (i = 0; i < (recordsPtr->len); i++)
	{
		packetPtr->rptr[i] = (DNSRecord*)malloc(sizeof(DNSRecord));
		*packetPtr->rptr[i] = recordsPtr->record[i];
	}
}

/*
* Unpack DNSPacket to DNSRecords
*/
void unpackDNSRecords(DNSPacket* packetPtr, DNSRecords* recordsPtr)
{
	int i;
	
	recordsPtr->len = packetPtr->header->ancount;
	recordsPtr->record = (DNSRecord*)malloc((packetPtr->header->ancount) * sizeof(DNSRecord));

	for (i = 0; i < (packetPtr->header->ancount); i++)
	{
		recordsPtr->record[i] = *packetPtr->rptr[i];
	}
}

void deleteDNSHeader(DNSHeader* headerPtr)
{
	free(headerPtr);
}

void deleteDNSQuery(DNSQuery* queryPtr)
{
	free(queryPtr->qname);
	free(queryPtr);
}

void deleteDNSRecord(DNSRecord* recordPtr)
{
	free(recordPtr->qname);
	free(recordPtr->rdata);
	free(recordPtr);
}

void deleteDNSRecords(DNSRecords* recordsPtr)
{
	free(recordsPtr->record);
	free(recordsPtr);
}

void deleteDNSPacket(DNSPacket* packetPtr)
{
	int i;
	for (i = 0; i < (packetPtr->header->qdcount); i++)
		deleteDNSQuery(packetPtr->qptr[i]);

	for (i = 0; i < (packetPtr->header->ancount); i++)
		deleteDNSRecord(packetPtr->rptr[i]);

	deleteDNSHeader(packetPtr->header);

	free(packetPtr);
}

char * typecodeToChar(int code) {
	switch(code){
		case 15:
			return "MX"; 
		case 5:
			return "CNAME"; 
		case 28:
			return "AAAA"; 
		case 1:
		default:
			return "A"; 		
	}
}

int charToTypecode(char * text) {
	if(!strcmp(text, "A")) return 1; 
	if(!strcmp(text, "AAAA")) return 28; 
	if(!strcmp(text, "CNAME")) return 5; 
	if(!strcmp(text, "MX")) return 15; 
	return -1; 
}

void debugDNSRecords(DNSRecords* recordsPtr)
{
	puts("===== Records =====");

	printf("length = %d\n", recordsPtr->len);
	
	int i;
	for (int i = 0; i < recordsPtr->len; i++)
	{
		printf("[%d] %d %d %d\n", i, recordsPtr->record[i].qname[0], recordsPtr->record[i].ttl, recordsPtr->record[i].rdata[0]);
	}

	puts("===================");
}

#endif