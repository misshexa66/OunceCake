// read only ftp, pushed to the switch 2
// eats the stuff (sdk functions etc.) smilebasic has
#include "native.h"
#define NONE 0xffffffffu
#define BAD 0xd401u
#define CFG_MAGIC 0x313050544632534eULL
#define INDEX_MAGIC 0x584950544632534eULL
#define PATH_BYTES 1024
#define NONBLOCK 0x800
#define DONTWAIT 0x80

void *memset(void *p, int value, __SIZE_TYPE__ n) {u8 *b=p; for (__SIZE_TYPE__ i=0;i<n;i++) b[i]=(u8)value; return p;}
void *memcpy(void *p, const void *q, __SIZE_TYPE__ n) {u8 *a=p;const u8 *b=q;for (__SIZE_TYPE__ i=0;i<n;i++) a[i]=b[i];return p;}
static u64 length(const char *s) {u64 n=0;while(s[n])n++;return n;}
static int equal(const char *a,const char *b) {u64 i=0;while(a[i]&&a[i]==b[i])i++;return a[i]==b[i];}
static int same(const void *a,const void *b,u64 n) {const u8 *x=a,*y=b;for(u64 i=0;i<n;i++)if(x[i]!=y[i])return 0;return 1;}
static u16 swap16(u16 n) {return (n>>8)|(n<<8);}
static int transient(FtpConfig *c) {int e=c->functions->get_errno();return e==4||e==11||e==35;}
// nagle + the client's delayed ack was holding every "226" back ~40ms, which murders small file downloads
static void no_delay(FtpConfig *c,int fd) {if(c->functions->setsockopt) {int one=1;c->functions->setsockopt(fd,6,1,&one,4);}}

typedef struct {
    FtpConfig *c;
    const Node *nodes;
    const char *strings;
    u64 count, string_bytes;
    u32 cache_source;
    u64 cache_offset, cache_bytes;
} Server;
typedef struct {
    Server *server;
    int control, passive;
    u32 cwd, binary;
    u64 restart;
    Address peer, local;
    char line[PATH_BYTES+1];
    u32 line_bytes;
} Client;
typedef struct {
    FtpConfig config;
    Server server;
    u64 thread;
    volatile u32 running;
    int control;
    Address peer;
} ClientSlot;
_Static_assert(sizeof(ClientSlot)<=4096, "client slot ABI");
static int io_enter(FtpConfig *c) {
    FtpConfig *owner=c->owner?(FtpConfig *)c->owner:c;
    while(__atomic_exchange_n(&owner->io_lock,1,__ATOMIC_ACQUIRE)) {
        if(c->stop)return 0;
        // we share fs connections. everyone play nice and wait for the system to finish your request
        PollFd delay={-1,0,0};
        c->functions->poll(&delay,1,1);
    }
    return 1;
}
static void io_leave(FtpConfig *c) {
    FtpConfig *owner=c->owner?(FtpConfig *)c->owner:c;
    __atomic_store_n(&owner->io_lock,0,__ATOMIC_RELEASE);
}
static u32 ipc_call(FtpConfig *c,u32 handle) {
    if(!io_enter(c))return BAD;
    u32 result=c->functions->ipc(c->ipc_buffer,4096,handle);
    io_leave(c);return result;
}

static int wait_fd(FtpConfig *c,int fd,short events,int attempts) {
    for(int i=0;i<attempts&&!c->stop;i++) {
        PollFd p={fd,events,0};int n=c->functions->poll(&p,1,100);
        if(n<0) {if(transient(c))continue;return -1;}
        if(n&&p.revents&events)return 1;
        if(n&&p.revents&0x38)return -1;
    }
    return 0;
}
static int send_all(FtpConfig *c,int fd,const void *data,u64 bytes,int payload) {
    u64 sent=0;
    while(sent<bytes&&!c->stop) {
        if(wait_fd(c,fd,4,300)!=1)return 0;
        s64 n=c->functions->send(fd,(const u8 *)data+sent,bytes-sent,DONTWAIT);
        if(n<0&&transient(c))continue;
        if(n<=0||(u64)n>bytes-sent)return 0;
        sent+=(u64)n;if(payload)c->sent+=(u64)n;
    }
    return sent==bytes;
}
static int reply(Client *p,const char *text) {return send_all(p->server->c,p->control,text,length(text),0);}
static u64 decimal(char *out,u64 value) {
    char reverse[20];u64 count=0;
    do {reverse[count++]=(char)('0'+value%10);value/=10;}while(value);
    for(u64 i=0;i<count;i++)out[i]=reverse[count-1-i];
    return count;
}
static int number(const char *s,u64 *out) {
    u64 n=0;if(!*s)return 0;
    for(;*s;s++) {if(*s<'0'||*s>'9'||n>(0xffffffffffffffffULL-(u64)(*s-'0'))/10)return 0;n=n*10+(u64)(*s-'0');}
    *out=n;return 1;
}
static int numeric_reply(Client *p,const char *prefix,u64 n) {
    char out[96];u64 at=length(prefix);memcpy(out,prefix,at);at+=decimal(out+at,n);out[at++]='\r';out[at++]='\n';
    return send_all(p->server->c,p->control,out,at,0);
}
static int string_valid(Server *s,u32 at,u64 limit) {
    if(at>=s->string_bytes)return 0;
    for(u64 i=0;i<=limit&&at+i<s->string_bytes;i++) {if(!s->strings[at+i])return 1;}
    return 0;
}
static int index_valid(Server *s) {
    FtpConfig *c=s->c;
    if(!c->index||c->index_bytes<64||c->source_count>0xffffffffULL||!c->sources||!c->source_count)return 0;
    const u64 *header=(const u64 *)c->index;
    if(header[0]!=INDEX_MAGIC||((const u32 *)header)[2]!=1||((const u32 *)header)[3]!=48||
        !header[2]||header[2]>=NONE||header[3]!=64||header[4]!=64+header[2]*48||header[6]!=c->index_bytes||
        header[4]>c->index_bytes||header[5]!=c->index_bytes-header[4])return 0;
    s->nodes=(const Node *)(c->index+64);s->count=header[2];s->strings=(const char *)c->index+header[4];s->string_bytes=header[5];
    for(u32 i=0;i<s->count;i++) {
        const Node *n=s->nodes+i;
        if(n->type>1||(!i&&(n->type||n->parent||n->name_length))||(i&&n->parent>=i)||
            n->name_length>=PATH_BYTES||!string_valid(s,n->name_offset,n->name_length)||
            length(s->strings+n->name_offset)!=n->name_length)return 0;
        const char *name=s->strings+n->name_offset;
        if(i&&(!n->name_length||equal(name,".")||equal(name,"..")))return 0;
        for(u32 j=0;j<n->name_length;j++)if(name[j]=='/'||name[j]=='\\'||name[j]=='\r'||name[j]=='\n')return 0;
        if(n->child!=NONE&&(n->type||n->child<=i||n->child>=s->count||s->nodes[n->child].parent!=i))return 0;
        if(!i&&n->next!=NONE)return 0;
        if(n->next!=NONE&&(n->next>=s->count||s->nodes[n->next].parent!=n->parent||n->next<=i))return 0;
        if(i&&s->nodes[n->parent].type)return 0;
        if(n->type) {
            if(n->mount>=c->source_count)return 0;
            const Source *source=c->sources+n->mount;
            if(!source->handle||source->kind>2||source->reserved||source->attributes>15||
                (source->kind!=2&&source->attributes)||n->offset+n->size<n->offset)return 0;
            if(source->kind!=1&&n->offset+n->size>source->size)return 0;
            if(source->kind&&(!string_valid(s,n->source_path,0x300)||
                s->strings[n->source_path]!=(source->kind==1?'/':'@')))return 0;
        }
    }
    return 1;
}
static u32 lookup(Client *p,const char *name) {
    Server *s=p->server;u32 current=*name=='/'?0:p->cwd;
    while(*name) {
        while(*name=='/')name++;
        const char *begin=name;while(*name&&*name!='/')name++;u64 n=(u64)(name-begin);
        if(!n)break;
        if(n==1&&*begin=='.')continue;
        if(n==2&&begin[0]=='.'&&begin[1]=='.') {current=s->nodes[current].parent;continue;}
        if(s->nodes[current].type)return NONE;
        u32 child=s->nodes[current].child,visited=0;
        while(child!=NONE&&visited++<s->count) {
            const Node *node=s->nodes+child;
            if(node->name_length==n&&same(s->strings+node->name_offset,begin,n))break;
            child=node->next;
        }
        if(child==NONE||visited>s->count)return NONE;
        current=child;
    }
    return current;
}
static int pwd(Client *p) {
    char out[PATH_BYTES+16];u32 chain[PATH_BYTES/2],count=0,current=p->cwd;u64 at=5;
    memcpy(out,"257 \"",5);
    while(current&&count<PATH_BYTES/2) {chain[count++]=current;current=p->server->nodes[current].parent;}
    if(current)return reply(p,"550 Path too long\r\n");
    out[at++]='/';
    while(count) {
        const Node *n=p->server->nodes+chain[--count];const char *name=p->server->strings+n->name_offset;
        for(u32 i=0;i<n->name_length;i++) {if(at+4>=sizeof(out))return reply(p,"550 Path too long\r\n");out[at++]=name[i];if(name[i]=='\"')out[at++]='\"';}
        if(count)out[at++]='/';
    }
    out[at++]='\"';out[at++]='\r';out[at++]='\n';return send_all(p->server->c,p->control,out,at,0);
}
static void passive_close(Client *p) {if(p->passive>=0) {p->server->c->functions->close(p->passive);p->passive=-1;}}
static int passive(Client *p,int extended) {
    FtpConfig *c=p->server->c;FtpFunctions *f=c->functions;passive_close(p);
    int fd=f->socket(2,1,0);if(fd<0)return reply(p,"425 Cannot create data socket\r\n");
    Address address={16,2,0,0,{0}};u32 size=16;
    if(f->bind(fd,&address,16)||f->listen(fd,1)||f->sockname(fd,&address,&size)||size!=16) {f->close(fd);return reply(p,"425 Cannot listen for data\r\n");}
    p->passive=fd;char out[160];u64 at;
    if(extended) {
        const char *prefix="229 Entering Extended Passive Mode (|||";at=length(prefix);memcpy(out,prefix,at);at+=decimal(out+at,swap16(address.port));
        memcpy(out+at,"|)\r\n",4);at+=4;
    } else {
        const char *prefix="227 Entering Passive Mode (";at=length(prefix);memcpy(out,prefix,at);
        const u8 *ip=(const u8 *)&p->local.address;
        for(u32 i=0;i<4;i++) {at+=decimal(out+at,ip[i]);out[at++]=',';}
        const u8 *port=(const u8 *)&address.port;at+=decimal(out+at,port[0]);out[at++]=',';at+=decimal(out+at,port[1]);memcpy(out+at,")\r\n",3);at+=3;
    }
    return send_all(c,p->control,out,at,0);
}
static int data_accept(Client *p) {
    FtpConfig *c=p->server->c;FtpFunctions *f=c->functions;
    if(p->passive<0)return -1;
    for(int i=0;i<300&&!c->stop;i++) {
        if(wait_fd(c,p->passive,1,1)!=1)continue;
        Address address={0};u32 size=16;int fd=f->accept(p->passive,&address,&size);
        if(fd<0)continue;
        if(size!=16||address.family!=2||address.address!=p->peer.address) {f->close(fd);continue;}
        no_delay(c,fd);passive_close(p);return fd;
    }
    passive_close(p);return -1;
}
static u64 fact_line(Server *s,const Node *n,char *out,int mode) {
    u64 at=0;const char *prefix;
    if(mode==2) {
        prefix=n->type?"type=file;size=":"type=dir;size=";at=length(prefix);memcpy(out,prefix,at);at+=decimal(out+at,n->size);
        prefix=";modify=19700101000000;perm=";memcpy(out+at,prefix,length(prefix));at+=length(prefix);
        prefix=n->type?"r; ":"el; ";memcpy(out+at,prefix,length(prefix));at+=length(prefix);
    } else if(mode==0) {
        prefix=n->type?"-r--r--r-- 1 ftp ftp ":"dr-xr-xr-x 1 ftp ftp ";at=length(prefix);memcpy(out,prefix,at);at+=decimal(out+at,n->size);
        prefix=" Jan 01  1970 ";memcpy(out+at,prefix,length(prefix));at+=length(prefix);
    }
    memcpy(out+at,s->strings+n->name_offset,n->name_length);at+=n->name_length;out[at++]='\r';out[at++]='\n';return at;
}
static int list(Client *p,const char *name,int mode) {
    if(mode==0)while(*name=='-') {while(*name&&*name!=' ')name++;while(*name==' ')name++;}
    u32 id=lookup(p,name);Server *s=p->server;
    if(id==NONE)return reply(p,"550 No such path\r\n");
    if(p->passive<0)return reply(p,"425 Use PASV or EPSV first\r\n");
    if(!reply(p,"150 Opening directory listing\r\n"))return 0;
    int fd=data_accept(p);if(fd<0)return reply(p,"425 Data connection unavailable\r\n");
    u32 at=s->nodes[id].type?id:s->nodes[id].child;int ok=1;u64 used=0;u32 visited=0;
    while(at!=NONE&&visited++<s->count&&ok&&!s->c->stop) {
        const Node *n=s->nodes+at;char line[PATH_BYTES+128];u64 bytes=fact_line(s,n,line,mode);
        if(used+bytes>s->c->data_bytes) {ok=send_all(s->c,fd,s->c->data,used,0);used=0;s->cache_source=NONE;}
        memcpy(s->c->data+used,line,bytes);used+=bytes;
        at=s->nodes[id].type?NONE:n->next;
    }
    if(ok&&used)ok=send_all(s->c,fd,s->c->data,used,0);
    s->cache_source=NONE;s->c->functions->close(fd);
    return reply(p,ok&&!s->c->stop?"226 Listing complete\r\n":"426 Listing interrupted\r\n");
}

// put together the fs ipc requests for downloads
static void packet(FtpConfig *c,u32 command,const void *input,u32 bytes,u8 *output,u32 count) {
    u32 *p=(u32 *)c->ipc_buffer;memset(p,0,256);p[0]=4|(count?1u<<24:0);p[1]=(32+bytes+3)/4;
    u32 at=16;
    if(count) {u64 a=(u64)output;p[2]=count;p[3]=(u32)a;p[4]=1u|((u32)(a>>36)<<2)|((u32)((a>>32)&15)<<28);at=32;}
    *(u32 *)((u8 *)p+at)=0x49434653;*(u32 *)((u8 *)p+at+8)=command;memcpy((u8 *)p+at+16,input,bytes);
}
static u8 *response(FtpConfig *c,u32 *moved) {
    u32 *p=(u32 *)c->ipc_buffer,at=2;*moved=0;
    if(p[1]>>31) {
        u32 special=p[at++],copies=(special>>1)&15,moves=(special>>5)&15;
        if(special&1)at+=2;
        if(copies||moves>1)return 0;
        if(moves)*moved=p[at++];
    }
    at+=((p[0]>>16)&15)*2+(((p[0]>>20)&15)+((p[0]>>24)&15)+((p[0]>>28)&15))*3;at=(at+3)&~3u;
    if(at+4>64||p[at]!=0x4f434653)return 0;
    if(p[at+2]) {c->native_result=p[at+2];return 0;}
    return (u8 *)(p+at+4);
}
static u32 open_source(Server *s,const Node *n) {
    FtpConfig *c=s->c;const char *filename=s->strings+n->source_path;u8 *name=c->ipc_buffer+4096;
    const Source *source=c->sources+n->mount;
    u64 bytes=length(filename);if(bytes>0x300)return 0;memset(name,0,0x301);memcpy(name,filename,bytes);
    u32 input[2]={source->kind==1?1:source->attributes,6};
    packet(c,source->kind==1?8:206,input,source->kind==1?4:8,0,0);u32 *p=(u32 *)c->ipc_buffer;u64 a=(u64)name;
    p[0]=4|1u<<16;p[2]=(0x301u<<16)|((u32)((a>>36)&7)<<6)|((u32)((a>>32)&15)<<12);p[3]=(u32)a;
    c->native_result=ipc_call(c,source->handle);if(c->native_result)return 0;
    u32 handle;if(!response(c,&handle)||!handle)return 0;
    if(source->kind==2) {
        packet(c,4,0,0,0,0);c->native_result=ipc_call(c,handle);
        u32 moved=0;u8 *out=c->native_result?0:response(c,&moved);
        if(!out||moved||*(u64 *)out!=source->size) {
            if(moved)c->functions->close_handle(moved);
            c->functions->close_handle(handle);return 0;
        }
    }
    return handle;
}
static int read_storage(Server *s,u32 handle,int file,u64 offset,u32 count) {
    FtpConfig *c=s->c;u64 input[3]={file?0:offset,file?offset:count,count};
    packet(c,0,input,file?24:16,c->data,count);
    c->native_result=ipc_call(c,handle);if(c->native_result)return 0;
    u32 moved;u8 *out=response(c,&moved);if(!out||moved)return 0;
    if(file&&*(u64 *)out!=count)return 0;
    return 1;
}
static int retrieve(Client *p,const char *name) {
    if(!p->binary) {
        passive_close(p);p->restart=0;
        return reply(p,"503 Downloading in ASCII mode forbidden. Set your client to TYPE I (ASCII) first\r\n");
    }
    Server *s=p->server;FtpConfig *c=s->c;u32 id=lookup(p,name);u64 restart=p->restart;p->restart=0;
    if(id==NONE||!s->nodes[id].type)return reply(p,"550 No such file\r\n");
    const Node *n=s->nodes+id;const Source *source=c->sources+n->mount;
    if(restart>n->size)return reply(p,"551 Restart offset exceeds file size\r\n");
    if(p->passive<0)return reply(p,"425 Use PASV or EPSV first\r\n");
    u32 handle=source->kind?open_source(s,n):source->handle;
    if(!handle)return reply(p,"550 Source file could not be opened\r\n");
    if(!reply(p,"150 Opening binary data connection\r\n")) {if(source->kind)c->functions->close_handle(handle);return 0;}
    int fd=data_accept(p),ok=fd>=0;u64 offset=restart;
    if(source->kind)s->cache_source=NONE;
    while(ok&&offset<n->size&&!c->stop) {
        u64 count,inside=0;
        if(source->kind==1) {
            count=n->size-offset;if(count>c->data_bytes)count=c->data_bytes;
            ok=read_storage(s,handle,1,offset,(u32)count);
        } else {
            u64 at=n->offset+offset,start=(at/c->data_bytes)*c->data_bytes;
            if(s->cache_source!=n->mount||s->cache_offset!=start) {
                count=source->size-start;if(count>c->data_bytes)count=c->data_bytes;
                ok=read_storage(s,handle,0,start,(u32)count);if(!ok)break;
                s->cache_source=n->mount;s->cache_offset=start;s->cache_bytes=count;
            }
            inside=at-s->cache_offset;count=s->cache_bytes-inside;if(count>n->size-offset)count=n->size-offset;
        }
        if(ok)ok=send_all(c,fd,c->data+inside,count,1);
        offset+=count;
    }
    if(fd>=0)c->functions->close(fd);
    if(source->kind) {if(c->functions->close_handle(handle))ok=0;s->cache_source=NONE;}
    if(ok&&offset==n->size&&!c->stop) {c->files++;return reply(p,"226 Transfer complete\r\n");}
    return reply(p,fd<0?"425 Data connection unavailable\r\n":"426 Transfer interrupted\r\n");
}
static int command(Client *p,char *line) {
    char *name=line;while(*line&&*line!=' ') {if(*line>='a'&&*line<='z')*line-=32;line++;}
    char *arg=line;if(*line) {*line++=0;arg=line;}
    if(equal(name,"QUIT")) {reply(p,"221 Goodbye\r\n");return 0;}
    if(equal(name,"NOOP"))return reply(p,"200 OK\r\n");
    if(equal(name,"SYST"))return reply(p,"215 UNIX Type: L8\r\n");
    if(equal(name,"FEAT"))return reply(p,"211-Features\r\n EPSV\r\n PASV\r\n SIZE\r\n MDTM\r\n MLST type*;size*;modify*;perm*;\r\n REST STREAM\r\n UTF8\r\n211 End\r\n");
    // ftp client might send name/pass, not needed
    if(equal(name,"USER")||equal(name,"PASS"))return reply(p,"230 Login not required\r\n");
    if(equal(name,"PWD")||equal(name,"XPWD"))return pwd(p);
    if(equal(name,"CWD")||equal(name,"CDUP")) {
        u32 id=lookup(p,equal(name,"CDUP")?"..":arg);
        if(id==NONE||p->server->nodes[id].type)return reply(p,"550 No such directory\r\n");
        p->cwd=id;return reply(p,"250 Directory changed\r\n");
    }
    if(equal(name,"TYPE")) {
        int binary=equal(arg,"I")||equal(arg,"i");
        if(!binary&&!equal(arg,"A")&&!equal(arg,"a"))return reply(p,"504 Unsupported type\r\n");
        p->binary=binary;return reply(p,"200 Type accepted\r\n");
    }
    if(equal(name,"MODE"))return reply(p,equal(arg,"S")?"200 Stream mode\r\n":"504 Unsupported mode\r\n");
    if(equal(name,"STRU"))return reply(p,equal(arg,"F")?"200 File structure\r\n":"504 Unsupported structure\r\n");
    if(equal(name,"OPTS"))return reply(p,equal(arg,"UTF8 ON")?"200 UTF8 enabled\r\n":"501 Unsupported option\r\n");
    if(equal(name,"REST")) {u64 at;if(!number(arg,&at))return reply(p,"501 Invalid restart offset\r\n");p->restart=at;return reply(p,"350 Restart offset accepted\r\n");}
    if(equal(name,"EPSV"))return passive(p,1);
    if(equal(name,"PASV"))return passive(p,0);
    if(equal(name,"LIST"))return list(p,arg,0);
    if(equal(name,"NLST"))return list(p,arg,1);
    if(equal(name,"MLSD"))return list(p,arg,2);
    if(equal(name,"MLST")) {
        u32 id=lookup(p,arg);if(id==NONE)return reply(p,"550 No such path\r\n");
        char out[PATH_BYTES+160];u64 at=14;memcpy(out,"250-Listing\r\n ",14);at+=fact_line(p->server,p->server->nodes+id,out+at,2);
        memcpy(out+at,"250 End\r\n",9);at+=9;return send_all(p->server->c,p->control,out,at,0);
    }
    if(equal(name,"SIZE")||equal(name,"MDTM")) {
        u32 id=lookup(p,arg);if(id==NONE||!p->server->nodes[id].type)return reply(p,"550 No such file\r\n");
        return equal(name,"SIZE")?numeric_reply(p,"213 ",p->server->nodes[id].size):reply(p,"213 19700101000000\r\n");
    }
    if(equal(name,"RETR"))return retrieve(p,arg);
    if(equal(name,"ABOR")) {passive_close(p);p->restart=0;return reply(p,"226 No transfer active\r\n");}
    return reply(p,"550 Read-only server or unsupported command\r\n");
}
static void session(Server *s,int fd,Address peer) {
    Client p;memset(&p,0,sizeof(p));p.server=s;p.control=fd;p.passive=-1;p.peer=peer;
    u32 size=16;if(s->c->functions->sockname(fd,&p.local,&size)||size!=16)return;
    memcpy(s->c->ip,&p.local.address,4);
    if(!reply(&p,"220 Selected game read-only FTP\r\n"))return;
    char input[512];u32 idle=0;int ok=1;
    while(ok&&!s->c->stop&&idle<3000) {
        int ready=wait_fd(s->c,fd,1,1);if(ready<0)break;if(!ready) {idle++;continue;}
        s64 count=s->c->functions->recv(fd,input,sizeof(input),DONTWAIT);
        if(count<0&&transient(s->c))continue;
        if(count<=0||count>(s64)sizeof(input))break;
        idle=0;
        for(s64 i=0;i<count&&ok;i++) {
            u8 b=(u8)input[i];
            if(!b||b==255) {reply(&p,"500 Invalid command encoding\r\n");ok=0;break;}
            if(b=='\n') {
                if(p.line_bytes&&p.line[p.line_bytes-1]=='\r')p.line_bytes--;
                p.line[p.line_bytes]=0;ok=command(&p,p.line);p.line_bytes=0;
            } else if(p.line_bytes==PATH_BYTES) {reply(&p,"500 Command too long\r\n");ok=0;}
            else p.line[p.line_bytes++]=(char)b;
        }
    }
    passive_close(&p);
}
static void *client_worker(void *argument) {
    ClientSlot *slot=argument;
    session(&slot->server,slot->control,slot->peer);
    slot->config.functions->close(slot->control);
    __atomic_store_n(&slot->running,0,__ATOMIC_RELEASE);
    return 0;
}
static void collect_clients(FtpConfig *c,int stop) {
    u64 sent=0,files=0;
    for(u32 i=0;i<c->reserved;i++) {
        ClientSlot *slot=(ClientSlot *)(c->slots+i*c->slot_bytes);
        if(stop)slot->config.stop=1;
        if(slot->thread&&!__atomic_load_n(&slot->running,__ATOMIC_ACQUIRE)) {
            if(c->functions->thread_join(slot->thread,0))c->result=BAD;
            else slot->thread=0;
        }
        sent+=slot->config.sent;files+=slot->config.files;
        if(slot->config.native_result)c->native_result=slot->config.native_result;
        if(slot->config.ip[0])memcpy(c->ip,slot->config.ip,4);
    }
    c->sent=sent;c->files=files;
}
void *ftp_main(void *configuration) {
    FtpConfig *c=configuration;
    if(!c||c->magic!=CFG_MAGIC||c->version!=1)return (void *)(u64)BAD;
    Server s;memset(&s,0,sizeof(s));s.c=c;s.cache_source=NONE;c->state=0;c->result=BAD;
    if(!c->functions||!c->ipc_buffer||!c->data||c->data_bytes<4096||c->data_bytes>0x400000||
        !c->port||c->port>65535||!c->slots||!c->reserved||c->reserved>FTP_MAX_CLIENTS||
        c->slot_bytes<4096+c->data_bytes+8192||!index_valid(&s)) {c->state=3;return (void *)(u64)BAD;}
    for(u32 i=0;i<c->reserved;i++)memset(c->slots+i*c->slot_bytes,0,sizeof(ClientSlot));
    FtpFunctions *f=c->functions;int fd=f->socket(2,1,0);
    if(fd<0) {c->state=3;return (void *)(u64)BAD;}
    Address address={16,2,swap16((u16)c->port),0,{0}};
    if(f->bind(fd,&address,16)||f->listen(fd,(int)c->reserved)) {f->close(fd);c->state=3;return (void *)(u64)BAD;}
    c->result=0;c->state=1;
    while(!c->stop) {
        collect_clients(c,0);
        int ready=wait_fd(c,fd,1,1);if(ready<0) {c->result=BAD;break;}if(!ready)continue;
        Address peer={0};u32 bytes=16;int client=f->accept(fd,&peer,&bytes);
        if(client<0)continue;
        no_delay(c,client);
        ClientSlot *slot=0;
        for(u32 i=0;i<c->reserved;i++) {
            ClientSlot *candidate=(ClientSlot *)(c->slots+i*c->slot_bytes);
            if(!candidate->thread) {slot=candidate;break;}
        }
        if(bytes!=16||peer.family!=2||!slot) {send_all(c,client,"421 Server busy\r\n",17,0);f->close(client);continue;}
        u64 sent=slot->config.sent,files=slot->config.files;
        memcpy(&slot->config,c,sizeof(*c));slot->config.sent=sent;slot->config.files=files;slot->config.owner=(struct FtpConfigTag *)c;
        slot->config.data=(u8 *)slot+4096;slot->config.ipc_buffer=slot->config.data+c->data_bytes;
        slot->server=s;slot->server.c=&slot->config;slot->server.cache_source=NONE;slot->control=client;slot->peer=peer;slot->running=1;
        if(f->thread_create(&slot->thread,0,client_worker,slot)) {slot->running=0;slot->thread=0;f->close(client);}
    }
    f->close(fd);
    for(;;) {
        collect_clients(c,1);int active=0;
        for(u32 i=0;i<c->reserved;i++)if(((ClientSlot *)(c->slots+i*c->slot_bytes))->thread)active=1;
        if(!active)break;
        PollFd delay={-1,0,0};f->poll(&delay,1,50);
    }
    c->state=c->result?3:2;return (void *)(u64)c->result;
}
