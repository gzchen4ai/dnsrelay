#include <string.h>

char * DATABASE_PATH; 
char * DNS_SERVER_IP; 
int DEBUG_LEVEL; 

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

void DEBUG3(const char *info, ...) {
	if(DEBUG_LEVEL < 3) return; 
	printf("[DETAIL]"); 
	va_list args; 
	va_start(args, info); 
	vprintf(info, args); 
	va_end(args); 
	puts(""); 
}

int init_opt(int argc, char* argv[]) {
	DEBUG_LEVEL = 0; 
	DNS_SERVER_IP = "114.114.114.114"; 
	DATABASE_PATH = "dnsrelay-edit3.txt"; 
	
	for(int i = 1; i < argc; i ++) {
		if(!strcmp(argv[i], "-d")) {
			DEBUG_LEVEL = 1; continue; 
		}
		if(!strcmp(argv[i], "-dd")) {
			DEBUG_LEVEL = 2; continue; 
		}
		if(!strcmp(argv[i], "-ddd")) {
			DEBUG_LEVEL = 3; continue; 
		}
		
		if(argv[i][0] >= '0' && argv[i][0] <= '9') {
			// ip address
			free(DNS_SERVER_IP); 
			DNS_SERVER_IP = (char*)malloc(strlen(argv[i]) * sizeof(char)); 
			memcpy(DNS_SERVER_IP, argv[i], strlen(argv[i])); 
			continue; 
		}
		
		// filename 
		free(DATABASE_PATH); 
		DATABASE_PATH = (char*)malloc(strlen(argv[i]) * sizeof(char)); 
		memcpy(DATABASE_PATH, argv[i], strlen(argv[i])); 
	}
}