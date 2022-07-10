#include <WinSock2.h>
#include <pthread.h>

#include "dnstrans.h"
#include "control.h"

#pragma comment(lib,"Ws2_32.lib")

#define BUF_SIZE 2048

void DEBUG0(const char *info, ...) {
	if(DEBUG_LEVEL < 0) return; 
	printf("[FATAL]"); 
	va_list args; 
	va_start(args, info);
	vprintf(info, args);  
	va_end(args); 
	puts(""); 
}


void DEBUG1(const char *info, ...) {
	if(DEBUG_LEVEL < 1) return; 
	printf("[ERROR]"); 
	va_list args; 
	va_start(args, info);
	vprintf(info, args);  
	va_end(args); 
	puts(""); 
}

void DEBUG2(const char *info, ...) {
	if(DEBUG_LEVEL < 2) return; 
	printf("[INFO]"); 
	va_list args; 
	va_start(args, info);
	vprintf(info, args);  
	va_end(args); 
	puts(""); 
}

struct DNSRequest{
	int id; 
	int org_id; 
	int req_size; 
	char request[BUF_SIZE]; 
	char response[BUF_SIZE]; 
	struct sockaddr_in client_addr; 	
};

SOCKET listenfd; 

struct DNSRequest request_q[10000]; 
int q_head = 0, q_tail = 0; 
// [q_head, q_tail)

bool queue_empty() {
	if(q_head >= 10000 && q_tail >= 10000) 
		q_head -= 10000, q_tail -= 10000; 
	return q_head == q_tail; 
}

int queue_push(struct DNSRequest req) {
	request_q[q_tail % 10000] = req; 
	return q_tail ++; 
}

struct DNSRequest queue_front() {
	return request_q[q_head % 10000]; 
}

void queue_pop() {
	if(queue_empty()) {
		DEBUG0("queue error"); 
	}
	else q_head ++; 
}

pthread_mutex_t q_lock; 
pthread_mutex_t malloc_lock; 

int socket_init() {
	int res = 0; 
	
	WORD socket_version = MAKEWORD(2, 2); 
	WSADATA wsadata; 
	
	res = WSAStartup(socket_version, &wsadata); 
	
	return res; 
}
void* handle_dns_request();
int dns_init() {
	int res = 0; 
	
	pthread_t th1; 
	pthread_t th2; 
	pthread_t th3; 
	pthread_t th4; 
	
	pthread_create(&th1, NULL, handle_dns_request, NULL); 
	pthread_create(&th2, NULL, handle_dns_request, NULL); 
	pthread_create(&th3, NULL, handle_dns_request, NULL); 
	pthread_create(&th4, NULL, handle_dns_request, NULL); 
	
	return res; 
}

void* handle_dns_request() {
	int res= 0; 
	SOCKET socketfd = socket(AF_INET, SOCK_DGRAM, 0); 
	
	struct sockaddr_in server_addr; 
	server_addr.sin_family = AF_INET; 
	server_addr.sin_port = htons(53);
	server_addr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);
	
	res = connect(socketfd, (LPSOCKADDR)&server_addr, sizeof(server_addr)); 
	
	while(1) {
		if(queue_empty()) {
			Sleep(20); 
			continue; 
		}
		
		pthread_mutex_lock(&q_lock); 
		if(queue_empty()) {
			pthread_mutex_unlock(&q_lock);
			continue; 
		}
		
		struct DNSRequest req = queue_front(); queue_pop(); 
		pthread_mutex_unlock(&q_lock); 
		
		DEBUG2("handling id:%d", req.id); 
		
		// cache
//		char *temp = get_ip(); 
		if(0) {
			
		} else {		
			sendto(socketfd, req.request, req.req_size, 0, (LPSOCKADDR)&server_addr, sizeof(server_addr)); 
			
			struct sockaddr_in addr; 
			size_t addr_len = sizeof(addr);  	
			res = recvfrom(socketfd, req.response, BUF_SIZE, 0, (LPSOCKADDR)&addr, (size_t*)&addr_len); 
			
			if(res <= 0) {
				DEBUG1("receive invalid packet from dns server"); 
			}
			
			for(int i = 0; i < res; i ++) printf("%x ", req.response[i]); puts(""); 
			
			// id -> orgid
			pthread_mutex_lock(&malloc_lock); 
			DNSPacket *dnspacket; 
			dnspacket = (DNSPacket*)malloc(sizeof(DNSPacket)); 
			toDNSPacket(dnspacket, req.response); 
			printf("Packet #qdcount=%d #ancount=%d\n",dnspacket->header->qdcount, dnspacket->header->ancount);
			dnspacket->header->id = req.org_id;
			
			char *temp; 
			printf("Packet #qdcount=%d #ancount=%d\n",dnspacket->header->qdcount, dnspacket->header->ancount);
			temp = fromDNSPacket(dnspacket, &res);  
			pthread_mutex_unlock(&malloc_lock); 
		
			// sendback
			DEBUG2("sendback id:%d", req.id); 
			sendto(listenfd, temp, res, 0, (LPSOCKADDR)&req.client_addr, sizeof(req.client_addr)); 
			
			free(temp); 
			deleteDNSPacket(dnspacket);
		}
	}
}

//int send_dns_request(char * request, int reqsize, char * response, SOCKET socketfd) {
//	int res = 0; 
//
////	char request[] = {0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x05, 0x62, 0x61, 0x69, 0x64, 0x75, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01};  
//
//	sendto(socketfd, request, reqsize, 0, (LPSOCKADDR)&server_addr, sizeof(server_addr)); 
//	
////	char response[BUF_SIZE]; 
//	struct sockaddr_in addr; 
//	size_t addr_len = sizeof(addr);  	
//	res = recvfrom(socketfd, response, BUF_SIZE, 0, (LPSOCKADDR)&addr, (size_t*)&addr_len); 
//	
////	printf("res:%d\n", res); 
//	closesocket(socketfd); 
//	return res; 
//}

void* listen_port() {
	DEBUG2("start listening");  
	int res = 0; 
	
	listenfd = socket(AF_INET, SOCK_DGRAM, 0); 
	
	struct sockaddr_in my_addr; 
	my_addr.sin_family = AF_INET; 
	my_addr.sin_port = htons(53); 
	my_addr.sin_addr.s_addr = INADDR_ANY; 
	
	res = bind(listenfd, (LPSOCKADDR)&my_addr, sizeof(my_addr)); 
//	printf("%s", inet_ntoa(my_addr.sin_addr)); 
	
	dns_init(); 
	
	char buf[BUF_SIZE];  
	struct sockaddr_in client_addr; 
	size_t addr_len = sizeof(client_addr); 
	
	while(1) {
		memset(buf, 0, sizeof(buf));
		  
		res = recvfrom(listenfd, buf, sizeof(buf), 0, (LPSOCKADDR)&client_addr, (size_t*)&addr_len);
		if(res <= 0) {
//			puts("received invalid request"); 
			continue; 
		}
		
		DEBUG2("recieve from: %s, id: %d", inet_ntoa(client_addr.sin_addr), q_tail); 
		for(int i = 0; i < res; i ++) printf("%x ", buf[i]); puts(""); 
		
		struct DNSRequest req;
		
		pthread_mutex_lock(&malloc_lock); 
		DNSPacket *dnspacket;  
		dnspacket = (DNSPacket*)malloc(sizeof(DNSPacket)); ; 
		
		DEBUG2("flag0"); 
		toDNSPacket(dnspacket, buf); 
//		printf("Packet #name=%s #type=%d #class=%d\n",dnspacket->qptr[0]->qname, dnspacket->qptr[0]->qtype, dnspacket->qptr[0]->qclass);
		req.org_id = dnspacket->header->id; 
		dnspacket->header->id = q_tail; 
		DEBUG2("flag1"); 
		
		char *temp; 
		printf("Packet #qdcount=%d #ancount=%d\n",dnspacket->header->qdcount, dnspacket->header->ancount);
		temp = fromDNSPacket(dnspacket, &req.req_size); 
		pthread_mutex_unlock(&malloc_lock); 
		if(req.req_size > BUF_SIZE) {
			DEBUG1("packet size exceed."); 
			continue; 
		}
		DEBUG2("flag2"); 
		memcpy(req.request, temp, req.req_size); 
		req.id = q_tail; 
		req.client_addr = client_addr;
		DEBUG2("flag3"); 
		queue_push(req); 
		
		DEBUG2("recieve finished. id: %d", req.id); 
		
		free(temp); 
		deleteDNSPacket(dnspacket); 
	}
	
	closesocekt(listenfd); 
	return res; 
}

void * handle_TTL() {
	while(1) {
		Sleep(1000);
		//  	
	}
}

int main(int argc, char* argv[]) {
	int res;
	
	res = init_opt(argc, argv);  
	DEBUG_LEVEL = 2; 
	DEBUG2("debug level: %d", DEBUG_LEVEL);
	DEBUG2("database path: %s", DATABASE_PATH); 
	DEBUG2("upper server ip: %s", DNS_SERVER_IP);  
	
	res = socket_init(); 
	if(res != 0) {
		DEBUG0("socket init error"); return res; 
	}

	pthread_mutex_init(&q_lock, NULL); 
	pthread_mutex_init(&malloc_lock, NULL); 
	
	pthread_t th_listen; 
	pthread_t th_ttl;  
	
	pthread_create(&th_listen, NULL, listen_port, NULL);
	pthread_create(&th_ttl, NULL, handle_TTL, NULL);  
		
	pthread_join(th_listen, NULL); 
	pthread_join(th_ttl, NULL); 
	
	WSACleanup(); 
	
	return 0; 
}