#ifndef ALL_H
#define ALL_H

#include <time.h>
#include <stdio.h>
#include <windows.h>
#include "dnstrans.h"

#define MAX_HEAP_SIZE 128
#define MAX_SIZE 128
#define MAX_LEN 128
#define MAX_LIST_SIZE 50000

typedef struct 
{
	int table[MAX_HEAP_SIZE*4];//
	int ttl[MAX_HEAP_SIZE*4];//time to live 
	int size; 
}heap;

typedef struct 
{
	char *table[MAX_SIZE];
	int head[MAX_SIZE*8];
	int next[MAX_SIZE];
}map;
typedef struct 
{
	map mp;
	heap hp;
	DNSRecords* table[MAX_LEN];
	char *address[MAX_LEN];
	int nxt[MAX_LEN],lst[MAX_LEN],head,tail;
}cache;
typedef struct 
{
	int cnt;
	int ch[MAX_LIST_SIZE][40];
	DNSRecords * table[MAX_LIST_SIZE];
}list;

void heap_init(heap *a)
{
	a->size=0;
}
void heap_insert(heap *a,int num,int time)
{
	int tmp;
	a->size++;
//	a->table[a->size] = (char*)malloc(sizeof(char)*strlen(ip));
//	strcpy(ip,a->table[a->size]);
	a->table[a->size]=num;
	a->ttl[a->size]=time;
	tmp=a->size;
	while(tmp>1)
	{
		if(a->ttl[tmp/2]<=a->ttl[tmp])
			break;
		int tmp2;
		int p;
		tmp2=a->ttl[tmp];
		a->ttl[tmp]=a->ttl[tmp/2];
		a->ttl[tmp/2]=tmp2;
		p=a->table[tmp];
		a->table[tmp]=a->table[tmp/2];
		a->table[tmp/2]=p;
		tmp/=2;
	}
}
void heap_erase(heap *a)
{
	int tmp2;
	int p;
	tmp2=a->ttl[1];
	a->ttl[1]=a->ttl[a->size];
	a->ttl[a->size]=tmp2;
	p=a->table[1];
	a->table[1]=a->table[a->size];
	a->table[a->size]=p;
//	free(a->table[a->size]);
	a->ttl[a->size]=0;
	a->size--;
	int tmp=1,nxt;
//	printf("%d\n",a->size);
	while(tmp*2<=a->size)
	{
		if(tmp*2==a->size||a->ttl[tmp*2]<a->ttl[tmp*2+1])
			nxt=tmp*2;
		else
			nxt=tmp*2+1;
		if(a->ttl[tmp]>a->ttl[tmp2])
		{
			tmp2=a->ttl[tmp];
			a->ttl[tmp]=a->ttl[nxt];
			a->ttl[nxt]=tmp2;
			p=a->table[tmp];
			a->table[tmp]=a->table[nxt];
			a->table[nxt]=p;
			tmp=nxt;
		}
	}
}
void map_init(map *a)
{
	memset(a->head,-1,sizeof(a->head));
	memset(a->next,-1,sizeof(a->next));
}
unsigned long long get_Hash(char *a)
{
	int i,l;
	unsigned long long ans=0;
//		puts("**");
	l=strlen(a);
//	printf("%d\n",l);
	for(i=0;i<l;i++)
		ans=ans*256+a[i]-'0'+1;
	return ans;
}
void map_insert(map *mp,char* str,int value)
{
	unsigned long long hash = get_Hash(str);
	int w=hash%(8*MAX_SIZE);
	mp->next[value]=mp->head[w];
	mp->head[w]=value;
	mp->table[value]=(char *)malloc(sizeof(char)*(strlen(str)+1));
	strcpy(mp->table[value],str); 
}
int map_find(map *mp,char *str)
{
	unsigned long long hash = get_Hash(str);
	int w=hash%(8*MAX_SIZE);
	int tmp=mp->head[w];		
//	puts("*");

//		printf("%d\n",tmp);
	while(tmp!=-1)
	{
		if(strcmp(mp->table[tmp],str)==0)
			return tmp;
		tmp=mp->next[tmp];
	}
	return -1;
}
void map_erase(map *mp,char *str)
{
	
	unsigned long long hash = get_Hash(str);
	int w=hash%(8*MAX_SIZE);
	int tmp=mp->head[w],lst;
	while(tmp!=-1)
	{
		if(strcmp(mp->table[tmp],str)==0)
		{
			if(tmp==mp->head[w])
			{
				mp->head[w]=mp->next[tmp];
				mp->next[tmp]=-1;
			}
			else
			{
				mp->next[lst]=mp->next[tmp];
				mp->next[tmp]=-1;
			}
			free(mp->table[tmp]);
		}
		else
		{
			lst=tmp;
			tmp=mp->next[tmp];
		}
	}
}

void cache_init(cache *a)
{
	int i;
	for(i=0;i<MAX_LEN-1;i++)
	{
		a->nxt[i]=i+1;
		a->lst[i+1]=i;
	}
	map_init(&(a->mp));
	heap_init(&(a->hp));
	a->lst[0]=-1,a->nxt[MAX_LEN-1]=-1;
	a->head=MAX_LEN-1,a->tail=0;
}
int cache_find_records(cache *a,char* address,DNSRecords *records)
{
	int lt,nt;
	if(map_find(&(a->mp),address)!=-1)//cache
	{
		int node=map_find(&(a->mp),address);

		if(node!=a->tail)
		{
			
			if(node==a->head)
			{
				lt=a->lst[node];
				a->nxt[lt]=-1;
				a->head=lt;
				a->nxt[node]=a->tail;
				a->lst[a->tail]=node;
				a->tail=node;	
				a->lst[node]=-1;
			}
			else
			{
				nt=a->nxt[node];
				lt=a->lst[node];
				a->lst[nt]=lt;
				a->nxt[lt]=nt;
				a->lst[node]=-1;
				a->nxt[node]=a->tail;				
				a->lst[a->tail]=node;
				a->tail=node;
			}
		}		
//		printf("%d\n",node);
//		printf("%d\n",a->table[node]->len);
		memcpy(records,a->table[node],sizeof(DNSRecords));
//		strcpy(a->table[node],ip);	
//		if(strcmp(ip,empty_Ip)==0)
//			return 0;
		return 1;
	}
	else
		return 0;
}
void cache_add(cache *a,char* address,DNSRecords* reports,int ttl)
{
	int lt;
	free(a->table[a->head]);
	free(a->address[a->head]);
//	a->table[a->head]=(DNSRecords *)malloc(sizeof(DNSRecords));
//	memcpy(a->table[a->head],reports,sizeof(DNSRecords));
	a->table[a->head]=reports;
	if(a->address[a->head]!=NULL)
		map_erase(&(a->mp),a->address[a->head]);
	a->address[a->head]=(char *)malloc(sizeof(char)*(strlen(address)+1));
	strcpy(a->address[a->head],address);
	map_insert(&(a->mp),a->address[a->head],a->head);
	
	heap_insert(&(a->hp),a->head,ttl);
	lt=a->lst[a->head];
	a->nxt[lt]=-1;
	a->head=lt;
	a->nxt[a->head]=a->tail;
	a->lst[a->tail]=a->head;
	a->tail=a->head;
	a->lst[a->head]=-1;
}
void cache_erase(cache *a,int w)//timeout
{
	int lt,nt;
//	printf("%d\n",a->table[w]->len);
	free(a->address[w]);
//	printf("* %p %d\n",a->table[w],w);
//	puts("*");
	free(a->table[w]);
	if(w==a->head)
		return ;
	if(w==a->tail)
	{
		nt=a->nxt[w];
		a->tail=nt;
		a->lst[nt]=-1;
		a->nxt[a->head]=w;
		a->lst[w]=a->head;
		a->nxt[w]=-1;
		a->head=w;
	}
	else
	{
		nt=a->nxt[w];
		lt=a->lst[w];
		a->nxt[lt]=nt;
		a->nxt[a->head]=w;
		a->lst[w]=a->head;
		a->nxt[w]=-1;
		a->lst[nt]=lt;
		a->head=w;
	}
}
int change(char ch)
{
	if(ch>='a'&&ch<='z')
		return ch-'a';
	if(ch>='0'&&ch<='9')
		return ch-'0'+26;
	if(ch=='.')
		return 36;
	if(ch=='-')
		return 37;
	if(ch=='+')
		return 38; 
}
void list_add(list *a,char *address,DNSRecords *reports)
{
	int tmp=0;
	int i,l=strlen(address);
//	printf("%d\n",l);
	for(i=0;i<l;i++)
	{
//		printf("%d %d\n",i,tmp);
		int val=change(*(address+i));
		if(a->ch[tmp][val]==0)
			a->ch[tmp][val]=++a->cnt;
		tmp=a->ch[tmp][val];
	}
//	a->table[tmp]=(char *)malloc(sizeof(char)*strlen(ip));
//	strcpy(ip,a->table[tmp]);
	a->table[tmp]=reports;
}
void list_init(list *a,char *path)
{
	const int INF=3600000;
	FILE *fp;
	a->cnt=0;
	fp=fopen(path,"r");
	char ch[1024],address[1024],cnt1,cnt2;
	char *buffer=(char *)malloc(sizeof(char)*1024);
	while(fgets(buffer,1023,fp))
	{
//		printf("%s",buffer);
		DNSRecord* record;
		DNSRecords* records=(DNSRecords*)malloc(sizeof(DNSRecords));
		
		int type,l=strlen(buffer),i,w,j,k,flag,now,now2,lim;
		flag=0,cnt1=0,cnt2=0,w=0,now=1,j=0,now2=0;
		char *c2;
		if(buffer[l-1]=='\n')
			l--;
		for(i=0;i<l;i++)
		{
			
			if(buffer[i]==' '&&flag<=1)
			{
				if(flag==0)
				{
					if(address[0]=='a'&&address[1]=='a')
						type=1,lim=17;
					else if(address[0]=='a')
						type=0,lim=4;
					else if(address[0]=='c')
						type=2;
					else if(address[0]=='m')
						type=3;
					flag=1;
				}
				else if(flag==1)
					flag=2;
			}
			else
			{
				if(flag==0)
				{
					if(buffer[i]>='A'&&buffer[i]<='Z')
						address[cnt1++]=buffer[i]-'A'+'a';
					else					
						address[cnt1++]=buffer[i];
//					printf("%d
				}
				else if(flag==1)
				{
					w=w*10+buffer[i]-'0';
					record=(DNSRecord*)malloc(sizeof(DNSRecord)*w);
					records->len=w;
					records->record=record;
				}
				else
				{
					if(buffer[i]==' '||buffer[i]=='.'&&now==6&&(type==0||type==1))
					{
						ch[cnt2]='\0';
//						printf("%s",ch);
						if(now==1)
						{
							char *c=(char*)malloc(sizeof(char)*(cnt2+1));
							strcpy(c,ch);
//							printf("%d %s\n",now,ch);
							(record+j)->qname=c;
								
							now++;
						}
						else if(now==6)
						{
							if(type==0||type==1)
							{
								if(now2==0)
									c2=(char*)malloc(sizeof(char)*(lim+1));
								unsigned short w2=0;
								for(k=0;k<cnt2;k++)
									w2=w2*10+ch[k]-'0';
//								printf("%d !! %d\n",now2,w2);
								*(c2+now2)=(char)w2;
	//							puts("*");
								now2++;
								if(now2==lim)
								{
									*(c2+now2)='\0';
									(record+j)->rdata=c2;
									
									now=1;
									(record+j)->ttl=INF;
									j++;
									now2=0;
								}
							}
							else
							{
								char *c=(char*)malloc(sizeof(char)*(cnt2+1));
								strcpy(c,ch);
								(record+j)->rdata=c;
								now=1;
								(record+j)->ttl=INF;
								j++;
							}
						}
						else
						{
							unsigned short w2=0;
							for(k=0;k<cnt2;k++)
								w2=w2*10+ch[k]-'0';
//							printf("%d %d %d\n",now,w2,cnt2);
							if(now==2)
								(record+j)->rtype=w2;
							else if(now==3)
								(record+j)->rclass=w2;
							else if(now==4)
								(record+j)->rdlength=w2;
							else if(now==5)
								(record+j)->pref=w2;
							now++;
						}
						cnt2=0;
					}
					else
					{
						ch[cnt2++]=buffer[i];
//						if(now==6)
//						printf("%d %d&&&&&&\n",buffer[i]-'0',cnt2);
					}
				}
			}
		}
//		puts("*");
		if(type==0||type==1)
		{ 
			unsigned short w2=0;
			for(k=0;k<cnt2;k++)
				w2=w2*10+ch[k]-'0';
			ch[cnt2]='\0';
			*(c2+now2)=(char)w2;
			now2++;
//			printf("%d %d %d\n",w2,now2,cnt2);
			*(c2+now2)='\0';
			cnt2=0;
			(record+j)->rdata=c2;
		}
		else
		{
			ch[cnt2]='\0';
			char *c=(char*)malloc(sizeof(char)*(cnt2+1));
			strcpy(c,ch);
			(record+j)->rdata=c;
			now=1;
			(record+j)->ttl=INF;
			j++;
		}
//		printf("%s",c2);
//		printf("%s\n",ch);
		(record+j)->ttl=INF;
		address[cnt1]='\0';
		list_add(a,address,records);
	}
	fclose(fp);
}
int list_find_records(list *a,char* address,DNSRecords *records)
{
	int tmp=0;
	int i,l=strlen(address);
	for(i=0;i<l;i++)
	{
		char ch=*(address+i);
		if(ch>='A'&&ch<='Z')
			ch=ch-'A'+'a'; 
//		printf("%d %d\n",i,tmp);
		int val=change(ch);
//		printf("%d\n",val);
		tmp=a->ch[tmp][val];
		if(tmp==0)
			return 0;
	}
	memcpy(records,a->table[tmp],sizeof(DNSRecords));
//	reports=a->table[tmp];
//	strcpy(a->table[tmp],ip);
	return 1;

}
cache Cache;
list List;
char empty_Ip[10]="0.0.0.0";
void change2_ttl(DNSRecords *records)
{
	int i;
//		puts("*");
//		printf("%d\n",records->len);
	for(i=0;i<records->len;i++)
		((records->record)+i)->ttl-=time(0);
}
DNSRecords* get_records(char *address)//
{
	DNSRecords* records;
	records = (DNSRecords*)malloc(sizeof(DNSRecords));
//	ip=(char *)malloc(sizeof(char)*256);


	
	if(list_find_records(&List,address,records))
	{
		DNSRecords *records2=(DNSRecords *)malloc(sizeof(DNSRecords));
		DNSRecord *record2=(DNSRecord *)malloc(sizeof(DNSRecord)*(records->len));
		memcpy(record2,records->record,sizeof(DNSRecord)*(records->len));
		records2->len=records->len;
		records2->record=record2;
		return records2;
	}

	if(cache_find_records(&Cache,address,records))
	{
//		printf("%d\n",records->len);
		DNSRecords *records2=(DNSRecords *)malloc(sizeof(DNSRecords));
		DNSRecord *record2=(DNSRecord *)malloc(sizeof(DNSRecord)*(records->len));
		memcpy(record2,records->record,sizeof(DNSRecord)*(records->len));
		records2->len=records->len;
		records2->record=record2;
		change2_ttl(records2);
		return records2;
	}
	return NULL;
//	if(find_records())
//	{
//		add(Cache,address,ip,ttl);
//		return ip;
//	} 
}
int change1_ttl(DNSRecords *records)
{
//	printf("%p\n",records);
	int i,mn=2000000000;
	for(i=0;i<records->len;i++)
	{
//		printf("%d\n",i); 
		((records->record)+i)->ttl+=time(0);
		if(((records->record)+i)->ttl<mn)
			mn=((records->record)+i)->ttl;
	}
	return mn;
}

void add(char *address,DNSRecords *records)
{
//	DNSrecords* new_ 
	if(map_find(&(Cache.mp),address)!=-1)
		return ;
	DNSRecords *records2=(DNSRecords *)malloc(sizeof(DNSRecords));
	DNSRecord *record2=(DNSRecord *)malloc(sizeof(DNSRecord)*(records->len));
	memcpy(record2,records->record,sizeof(DNSRecord)*(records->len));
//	memcpy(records2,records,sizeof(DNSRecords));
	//puts("*");
	records2->len=records->len;
	records2->record=record2;
//	puts("*");
//	printf("%d %p %p\n",((records->record)+0)->ttl,records,records2);
	int ttl=change1_ttl(records2);
//	printf("%d %p %p\n",((records2->record)+0)->ttl,records,records2);
	if(ttl<=0)
		return;
	cache_add(&Cache,address,records2,ttl);
}
int check_ttl(DNSRecords *records)
{
	int i,mn=2000000000;
	for(i=0;i<records->len;i++)
	{
		if(((records->record)+i)->ttl<mn)
			mn=((records->record)+i)->ttl;
	}
	if(mn<=time(0))
		return 1;
	return 0;
}
void time_flip()//once per sec
{
	while(Cache.hp.size>0&&time(0)>=Cache.hp.ttl[1])
	{
		int w=Cache.hp.table[1];
		if(check_ttl(Cache.table[w]))
		{
			map_erase(&(Cache.mp),Cache.address[w]);
//			printf("%d\n",w);
			cache_erase(&Cache,w);
		}
		heap_erase(&(Cache.hp));
//	puts("*");
	}
}

int all_init(char * path) {
	cache_init(&Cache);
	list_init(&List,path);
	return 0; 
}

//int main()
//{
//

//	DNSRecord record;
//	DNSRecords* records=(DNSRecords *)malloc(sizeof(DNSRecords));
//	DNSRecords* r2;
//	records->record=&record;
//	records->len=1;
////	char a[100]="a+www.baidu.com";
//	char a[100]="A+ec.razer.com";
////	record.ttl=2;
////	record.rtype=1;
////	printf("* %p\n",records);
////	add(a,records);
////	Sleep(3000);
////	time_flip();
////	puts("*");
//	r2=get_records(a);
//	if(r2==NULL)
//		puts("!!!");
//	else
//		printf("%d %d %d %s\n",r2->len,r2->record->ttl,r2->record->rtype,r2->record->rdata);
//	return 0;
//	
//}
#endif