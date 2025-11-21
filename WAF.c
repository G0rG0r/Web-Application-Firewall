#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
unsigned long long Ehash(const unsigned char *har) {
    // my handy custom hashing algo :)
  unsigned long long h = 0x2434255344FULL;
  int x;
  while ((x = *har++))
    h = h * 33 + x;
  return h;
}

struct Client{
SOCKET fd;
struct sockaddr_in cInfo;
int sLen;
bool isVerified;
};
char *CreateToken() {
  
  FILE *Tokens = fopen("config/tokens.txt", "a+");
  if (!Tokens) return NULL;

  srand(time(NULL));
  int r = rand();

  char buf[32];
  snprintf(buf, sizeof(buf), "%d", r);

  unsigned long long h = Ehash((unsigned char *)buf);

  fprintf(Tokens, "%llx\n", h);
  fclose(Tokens);

  static char token[32];
  snprintf(token, sizeof(token), "%llx", h);
  return token;
}

void servefile(SOCKET fd, const char *filepath) {
  const char *contentType = "application/octet-stream";
  if (strstr(filepath, ".html")) {
    contentType = "text/html";
  } else if (strstr(filepath, ".png")) {
    contentType = "image/png";
  } 
  FILE *file = fopen(filepath, "rb"); 
  
  if (file == NULL) {
    const char *notFound = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    send(fd, notFound, strlen(notFound), 0);
    return; 
  }

  fseek(file, 0, SEEK_END);
  long fileSize = ftell(file);
  fseek(file, 0, SEEK_SET);

  char header[512];
  int headerLen = snprintf(header, sizeof(header), 
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: %s\r\n"
    "Content-Length: %ld\r\n" 
    "Connection: close\r\n" 
    "\r\n", 
    contentType, fileSize);
  
  send(fd, header, headerLen, 0);

  char file_buffer[4048];
  size_t n_read;
  while((n_read = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0){
    send(fd, file_buffer, n_read, 0); 
  }

  fclose(file); 
}
bool checkToken(const char *token) {
  FILE *Tokens = fopen("config/tokens.txt", "r");
  if (!Tokens) return false;

  char line[64];
  while (fgets(line, sizeof(line), Tokens)) {
    line[strcspn(line, "\n")] = 0;
    if (strcmp(line, token) == 0) {
      fclose(Tokens); 
      return true;
    }
  }

  fclose(Tokens);
  return false;
}
FILE *BannedFormats;
FILE *BannedRequests;
FILE *Configureations;
FILE *AllowedRequests;

DWORD WINAPI NewClient(LPVOID paramter){
   Configureations = fopen("config/config.txt","r");
   if(Configureations ==NULL){
     exit(EXIT_FAILURE);
 }
 struct Client* c = (struct Client*)paramter;
 printf("New client joined.\n");
 char buffer[4048];
 struct sockaddr_in server;
 char line[32];
 char ExtractedIP[16];
 int port;
 int secLvl;
 
 
 while(fgets(line,sizeof(line),Configureations) != NULL){
  if(sscanf(line,"IP Address:%15s",&ExtractedIP)){
   server.sin_addr.s_addr = inet_addr(ExtractedIP);
  }
  if(sscanf(line,"Port:%d",&port)){
   server.sin_port = htons(port);
  }
  if(sscanf(line,"Security Level:%d",&secLvl)){
  }
 }
  fclose(Configureations); 
  
 server.sin_family = AF_INET;
 SOCKET behalfFd = INVALID_SOCKET;
 int bytes_received = 0;
 int handled = 0; 
 
 while ((bytes_received = recv(c->fd, buffer, sizeof(buffer) - 1, 0)) > 0)
 {
  buffer[bytes_received] = '\0';
  

  char FindToken[64] = {0};
  char *cookie = strstr(buffer, "Cookie:");
  
  if (cookie != NULL) { 
   char *TokenStart = strstr(cookie, "waf_verified="); 
   
   if (TokenStart != NULL) {
    TokenStart += strlen("waf_verified=");
    size_t i;
    for (i = 0; isxdigit(TokenStart[i]) && i < sizeof(FindToken) - 1; i++) {
     FindToken[i] = TokenStart[i];
    }
    FindToken[i] = '\0';
    
    if(checkToken(FindToken)){
     c->isVerified = true;
    }
   }
  }
  
  char path[256];
  char method[8];
  sscanf(buffer, "%s %s", method, path);
  
  if (c->isVerified && secLvl == 1) {
   printf("Client Verified. Running WAF...\n");
   
   char *query_start = strchr(path, '?'); 
   if (query_start != NULL) {
    *query_start = '\0'; 
   }
      
      bool is_blocked = false; 

   BannedFormats = fopen("config/BannedFormats.txt","r");
      if (BannedFormats != NULL) {
    char lineCase[64]; 
        
        
    while (fgets(lineCase, sizeof(lineCase), BannedFormats)) {
     lineCase[strcspn(lineCase, "\n")] = 0; 
    
     if (strstr(buffer, lineCase) != NULL) {
     
            printf("Client BLOCKED for malicious request (Rule: '%s').\n", lineCase);
            
          
      BannedRequests = fopen("Logs/BannedRequests.txt","a");
      if (BannedRequests != NULL) {
       fprintf(BannedRequests,"======================= { BLOCKED } =======================\n");
       fprintf(BannedRequests,"Blocked Rule: %s\n", lineCase);
       fprintf(BannedRequests,"Request:\n%s\n",buffer);
       time_t x = time(NULL);
       struct tm *t = localtime(&x);
       char Timebuffer[80];
       strftime(Timebuffer, sizeof(Timebuffer), "%Y-%m-%d %H:%M:%S", t);
       fprintf(BannedRequests,"Blocked Time: %s\n",Timebuffer);
      
       fprintf(BannedRequests,"IP: %s\n", inet_ntoa(c->cInfo.sin_addr));
       fprintf(BannedRequests,"===========================================================\n");
       fclose(BannedRequests);
            }
            
            servefile(c->fd, "Pages/badrequest.html");
            is_blocked = true; 
            break; 
     }
    }
    fclose(BannedFormats);
      } else {
        fprintf(stderr, "WAF Warning: Could not open BannedFormats.txt.\n");
      }
      
      if (!is_blocked) {
        behalfFd = socket(AF_INET,SOCK_STREAM,0);
    if (connect(behalfFd,(struct sockaddr*)&server,sizeof(server)) == 0) {
     DWORD timeout = 500;
     setsockopt(behalfFd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
     send(behalfFd,buffer,bytes_received,0);
     char responseBuffer[4096];
     int responseBytes;
     while((responseBytes = recv(behalfFd, responseBuffer, sizeof(responseBuffer), 0)) > 0){
      send(c->fd,responseBuffer,responseBytes,0);
      printf("Request Allowed header %.16s\n",buffer);
      AllowedRequests = fopen("Logs/AllowedRequests.txt","a");
      fprintf(AllowedRequests,"=============++====={ Allowed }=====================\n");
      fprintf(AllowedRequests,"%s\n",buffer);
      fprintf(AllowedRequests,"IP: %s\n",inet_ntoa(c->cInfo.sin_addr));
      fprintf(AllowedRequests,"====================================================\n");
      fclose(AllowedRequests);
     }
     closesocket(behalfFd);
    }
      }
   handled = 1;

  } else {

   if (strcmp(method, "POST") == 0) {
    char *newToken = CreateToken();
    char response_header[512];
    int headelen = snprintf(response_header,sizeof(response_header),
     "HTTP/1.1 200 OK\r\n"
     "Content-Length: 0\r\n"
     "Set-Cookie: waf_verified=%s; Max-Age=3600; HttpOnly\r\n"
     "\r\n", newToken
    );
    send(c->fd, response_header, headelen, 0);
    handled = 1;
   
   } else if (strcmp(method, "GET") == 0) {
    char *fpath = path + 1;
    
    if(strlen(fpath)==0 || strcmp(fpath,"/")==0) fpath = "Pages/humanVerify.html";
    
    printf("Client Unverified. Serving WAF file \n");
    servefile(c->fd,fpath);
    handled = 1;
   
   } 
  }
 }

 if (behalfFd != INVALID_SOCKET) closesocket(behalfFd);
 closesocket(c->fd);
 free(c);
  printf("Client disconnected.\n");
return 0;
}


int main (){
WSADATA data;
WSAStartup(MAKEWORD(2,2),&data);
struct sockaddr_in ServerInfo;
SOCKET ServerSocket = socket(AF_INET,SOCK_STREAM,0);
ServerInfo.sin_addr.s_addr = inet_addr("0.0.0.0");
ServerInfo.sin_family = AF_INET;
ServerInfo.sin_port=htons(80);

bind(ServerSocket,(struct sockaddr*)&ServerInfo,sizeof(ServerInfo));
listen(ServerSocket,SOMAXCONN);
printf("Listening\n");
while(1){
struct Client *c = malloc(sizeof(struct Client));
c->sLen = sizeof(c->cInfo);
c->isVerified=0;
c->fd = accept(ServerSocket,(struct sockaddr*)&c->cInfo,&c->sLen);
if(c->fd ==INVALID_SOCKET){
closesocket(c->fd);
}
CreateThread(NULL,0,NewClient,(LPVOID)c,0,NULL);
}
}