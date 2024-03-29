#include <WinSock2.h>
#include <pthread.h>

#include "dnstrans.h"
#include "control.h"
#include "all.h"

#pragma comment(lib, "Ws2_32.lib")

#define BUF_SIZE 512
#define QUEUE_SIZE 10000
#define TIMEOUT_USEC 3000

struct DNSRequest {
	int id;
	char org_id[2];
	int req_size;
	char request[BUF_SIZE];
	char response[BUF_SIZE];
	struct sockaddr_in client_addr;
	bool finished;
};

SOCKET listenfd;

// request handle queue
// [q_head, q_tail)
struct DNSRequest request_q[QUEUE_SIZE];
int q_head = 0, q_tail = 0;

int queue_add(int x)
{
	return (x + 1) >= QUEUE_SIZE ? x + 1 - QUEUE_SIZE : x + 1;
}

bool queue_empty()
{
	return q_head == q_tail;
}

int queue_push(struct DNSRequest req)
{
	if (queue_add(q_tail) == q_head) {
		DEBUG0("queue overflow");
	}
	request_q[q_tail] = req;
	return q_tail = queue_add(q_tail);
}

struct DNSRequest queue_front()
{
	if (queue_empty()) {
		DEBUG0("queue error");
	}
	return request_q[q_head];
}

void queue_pop()
{
	if (queue_empty()) {
		DEBUG0("queue error");
	} else
		q_head = queue_add(q_head);
}

int chartoint(char c)
{
	return c >= 0 ? c : 256 + c;
}

pthread_mutex_t q_lock;
pthread_mutex_t cache_lock;

/*
* socket_init()
* initialize socket settings
*/
int socket_init()
{
	int res = 0;

	WORD socket_version = MAKEWORD(2, 2);
	WSADATA wsadata;

	res = WSAStartup(socket_version, &wsadata);

	return res;
}

void *handle_dns_request()
{
	int res = 0;
	SOCKET socketfd = socket(AF_INET, SOCK_DGRAM, 0);

	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(53);
	server_addr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

	res = connect(socketfd, (LPSOCKADDR)&server_addr, sizeof(server_addr));
	if (res != 0) {
		DEBUG0("failed to connect to upper name server");
		return NULL;
	}

	int timeoutusec = TIMEOUT_USEC;
	res = setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, &timeoutusec,
			 sizeof(timeoutusec));
	if (res != 0) {
		DEBUG1("timeout setting failed");
	}

	while (1) {
		if (queue_empty()) {
			Sleep(20);
			continue;
		}

		pthread_mutex_lock(&q_lock);
		if (queue_empty()) {
			pthread_mutex_unlock(&q_lock);
			continue;
		}

		struct DNSRequest req = queue_front();
		queue_pop();
		DEBUG2("handling id: %d", req.id);
		pthread_mutex_unlock(&q_lock);

		pDNSPacket dnspacket = (DNSPacket *)malloc(sizeof(DNSPacket));
		toDNSPacket(dnspacket, req.request);

		// compute cache address
		char *cache_type = typecodeToChar(dnspacket->qptr[0]->qtype);
		int cache_type_len = strlen(cache_type);
		char *cache_address = (char *)malloc(
			cache_type_len + 2 + strlen(dnspacket->qptr[0]->qname));
		memcpy(cache_address, cache_type, cache_type_len);
		memcpy(cache_address + cache_type_len + 1,
		       dnspacket->qptr[0]->qname,
		       strlen(dnspacket->qptr[0]->qname));
		cache_address[cache_type_len] = '+';
		cache_address[cache_type_len + 1 +
			      strlen(dnspacket->qptr[0]->qname)] = 0;
		DEBUG2("get cache: cache address=%s", cache_address);

		// get RRs from cache
		pthread_mutex_lock(&cache_lock);
		pDNSRecords cache_answer = get_records(cache_address);
		pthread_mutex_unlock(&cache_lock);
		free(cache_address);

		if (cache_answer != NULL) {
			// cache found
			DEBUG2("cache found");
			debugDNSRecords(cache_answer);
			DEBUG2("cache len: %d", cache_answer->len);
			appendDNSRecords(dnspacket, cache_answer);
			DEBUG2("cache qname: %s", dnspacket->rptr[0]->qname);
			if ((*(long long *)(cache_answer->record->rdata)) ==
			    0ll)
				continue;
			char *temp = fromDNSPacket(dnspacket, &res);
			temp[0] = req.org_id[0];
			temp[1] = req.org_id[1];
			res = sendto(listenfd, temp, res, 0,
				     (LPSOCKADDR)&req.client_addr,
				     sizeof(req.client_addr));
			free(temp);
			DEBUG2("cache sent");
		} else {
			// cache not found
			DEBUG2("cache not found");
			deleteDNSPacket(dnspacket);

			res = sendto(socketfd, req.request, req.req_size, 0,
				     (LPSOCKADDR)&server_addr,
				     sizeof(server_addr));
			if (res <= 0) {
				DEBUG1("failed to send request to upper dns server");
				continue;
			}

			struct sockaddr_in addr;
			size_t addr_len = sizeof(addr);

			do {
				res = recvfrom(socketfd, req.response, BUF_SIZE,
					       0, (LPSOCKADDR)&addr,
					       (size_t *)&addr_len);

				if (res <= 0) {
					DEBUG1("recevied invalid packet from upper server, code: %d",
					       res);
					break;
				}

				int id = chartoint(req.response[0]) * 256 +
					 chartoint(req.response[1]);
				DEBUG2("received response, id: %d", id);

				if (DEBUG_LEVEL > 2) {
					printf("response packet:\n");
					for (int i = 0; i < res; i++)
						printf("%#hx ",
						       req.response[i]);
					puts("");
				}

				// add cache
				pDNSPacket dnspacket =
					(DNSPacket *)malloc(sizeof(DNSPacket));
				toDNSPacket(dnspacket, req.response);
				pDNSRecords records = (DNSRecords *)malloc(
					sizeof(DNSRecords));
				unpackDNSRecords(dnspacket, records);

				if (records->len > 0) {
					DEBUG2("add cache");
					DEBUG2("cache len: %d",
					       dnspacket->header->ancount);
					debugDNSRecords(records);

					// compute cache address
					char *cache_type = typecodeToChar(
						dnspacket->qptr[0]->qtype);
					int cache_type_len = strlen(cache_type);
					char *cache_address = (char *)malloc(
						cache_type_len + 2 +
						strlen(dnspacket->qptr[0]
							       ->qname));
					memcpy(cache_address, cache_type,
					       cache_type_len);
					memcpy(cache_address + cache_type_len +
						       1,
					       dnspacket->qptr[0]->qname,
					       strlen(dnspacket->qptr[0]
							      ->qname));
					cache_address[cache_type_len] = '+';
					cache_address[cache_type_len + 1 +
						      strlen(dnspacket->qptr[0]
								     ->qname)] =
						0;

					// push RRs to cache
					pthread_mutex_lock(&cache_lock);
					add(cache_address, records);
					pthread_mutex_unlock(&cache_lock);
					free(cache_address);
					free(cache_type);
				}

				// id -> orgid
				req.response[0] = req.org_id[0];
				req.response[1] = req.org_id[1];

				if (id != req.id) {
					if (request_q[id].finished == 1)
						continue;

					// sendback
					DEBUG2("REsendback id: %d",
					       request_q[id].id);
					sendto(listenfd, req.response, res, 0,
					       (LPSOCKADDR)&request_q[id]
						       .client_addr,
					       sizeof(request_q[id]
							      .client_addr));
					request_q[id].finished = 1;
					continue;
				}

				// sendback
				DEBUG2("sendback id:%d", req.id);
				sendto(listenfd, req.response, res, 0,
				       (LPSOCKADDR)&req.client_addr,
				       sizeof(req.client_addr));
				request_q[id].finished = 1;
				break;
			} while (1);
		}
	}
}

int dns_init()
{
	pthread_t th1;
	pthread_t th2;
	pthread_t th3;
	pthread_t th4;

	pthread_create(&th1, NULL, handle_dns_request, NULL);
	pthread_create(&th2, NULL, handle_dns_request, NULL);
	pthread_create(&th3, NULL, handle_dns_request, NULL);
	pthread_create(&th4, NULL, handle_dns_request, NULL);

	return 0;
}

void *listen_port()
{
	DEBUG2("start listening");
	int res = 0;

	listenfd = socket(AF_INET, SOCK_DGRAM, 0);

	struct sockaddr_in my_addr;
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(53);
	my_addr.sin_addr.s_addr = INADDR_ANY;

	res = bind(listenfd, (LPSOCKADDR)&my_addr, sizeof(my_addr));

	dns_init();

	char buf[BUF_SIZE];
	struct sockaddr_in client_addr;
	size_t addr_len = sizeof(client_addr);

	while (1) {
		memset(buf, 0, sizeof(buf));

		res = recvfrom(listenfd, buf, sizeof(buf), 0,
			       (LPSOCKADDR)&client_addr, (size_t *)&addr_len);
		if (res <= 0) {
			DEBUG2("received invalid request");
			continue;
		}

		DEBUG2("recieved request from: %s, id: %d",
		       inet_ntoa(client_addr.sin_addr), q_tail);
		if (DEBUG_LEVEL > 2) {
			printf("request packet:\n");
			for (int i = 0; i < res; i++)
				printf("%#hx ", buf[i]);
			puts("");
		}

		struct DNSRequest req;

		memcpy(req.request, buf, res);
		req.client_addr = client_addr;
		req.req_size = res;
		req.finished = 0;

		// org_id -> id
		req.org_id[0] = buf[0];
		req.org_id[1] = buf[1];
		req.id = q_tail;
		req.request[0] = (char)(req.id / 256);
		req.request[1] = (char)(req.id % 256);
		DEBUG2("transaction id: %d -> %#hx %#hx", req.id,
		       req.request[0], req.request[1]);

		queue_push(req);
	}

	closesocket(listenfd);
	return res;
}

void *handle_TTL()
{
	while (1) {
		Sleep(1000);
		DEBUG2("start checking TTL");
		pthread_mutex_lock(&cache_lock);
		time_flip();
		pthread_mutex_unlock(&cache_lock);
		DEBUG2("end checking TTL");
	}
}

int main(int argc, char *argv[])
{
	int res = init_opt(argc, argv);
	res = all_init(DATABASE_PATH);

	if (res != 0) {
		DEBUG0("database init error");
		return res;
	}

	DEBUG_LEVEL = 3;
	DEBUG2("debug level: %d", DEBUG_LEVEL);
	DEBUG2("database path: %s", DATABASE_PATH);
	DEBUG2("upper server ip: %s", DNS_SERVER_IP);

	res = socket_init();
	if (res != 0) {
		DEBUG0("socket init error");
		return res;
	}

	pthread_mutex_init(&q_lock, NULL);
	pthread_mutex_init(&cache_lock, NULL);

	pthread_t th_listen;
	pthread_t th_ttl;

	pthread_create(&th_listen, NULL, listen_port, NULL);
	pthread_create(&th_ttl, NULL, handle_TTL, NULL);

	pthread_join(th_listen, NULL);

	WSACleanup();

	return 0;
}