#include <ec.h>                        /* required for global variables */
#include <ec_plugins.h>                /* required for plugin ops */
#include <ec_packet.h>
#include <ec_hook.h>
#include <ec_mitm.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

struct ip_stat_holder {
    char * ip;
    uint bytes;

    struct ip_stat_holder * next;
};

struct port_stat_holder {
    uint port;
    uint bytes;

    struct port_stat_holder * next;
};

struct ip_stat_holder * ip_stat_holder_ll_head = NULL;
struct port_stat_holder * port_stat_holder_ll_head = NULL;

int plugin_load(void *);

static int stat_exporter_init(void *);
static int stat_exporter_fini(void *);

static void parse_tcp(struct packet_object *);

static void add_ip_bytes(char *, uint);
static struct ip_stat_holder * create_ip_stat(char *, uint);
static void clear_ip_stats();

static void add_port_bytes(uint, uint);
static struct port_stat_holder * create_port_stat(uint, uint);
static void clear_port_stats();

int exporter_delay = 60;
int exporter_enabled = 0;

pthread_t exporter_thread;
pthread_mutex_t read_lock;
static void pthread_exporter(void *);

const size_t MAX_CONV_ID_LEN = 256;
const size_t JSON_BUFF_LEN = (1024 * 1024);


struct plugin_ops stat_exporter_ops = {
   .ettercap_version =  EC_VERSION,
   .name =              "stat_exporter",                   
   .info =              "Exports network usage statistics to a JSON file",
   .version =           "1.0",
   .init =              &stat_exporter_init,                    
   .fini =              &stat_exporter_fini,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   return plugin_register(handle, &stat_exporter_ops);
}

/*********************************************************/

static int stat_exporter_init(void *dummy) 
{
   USER_MSG("STAT_EXPORTER: stat_exporter running\n");

   hook_add(HOOK_PACKET_TCP, &parse_tcp);

   exporter_enabled = 1;
   if (pthread_create(&exporter_thread, NULL, &pthread_exporter, NULL))
   {
       USER_MSG("STAT_EXPORTER: failed to create exporter thread!\n");
   }

   return PLUGIN_RUNNING;
}


static int stat_exporter_fini(void *dummy) 
{
   USER_MSG("STAT_EXPORTER: stat_exporter stopped\n");

   hook_del(HOOK_PACKET_TCP, &parse_tcp);

   exporter_enabled = 0;

   USER_MSG("STAT_EXPORTER: Waiting for exporter thread to stop\n");

   if (pthread_join(exporter_thread, NULL))
   {
       USER_MSG("STAT_EXPORTER: Failed to join with exporter thread\n");
   }

   return PLUGIN_FINISHED;
}

static void parse_tcp(struct packet_object *po)
{
    // ignore our own traffic for now...
    if (ip_addr_is_ours(&po->L3.src) == E_FOUND || ip_addr_is_ours(&po->L3.dst) == E_FOUND)
    {
        return;
    }

    char src_addr[MAX_ASCII_ADDR_LEN];
    char dst_addr[MAX_ASCII_ADDR_LEN];
    uint pkt_len = po->DATA.len;

    ip_addr_ntoa(&po->L3.src, src_addr);
    ip_addr_ntoa(&po->L3.dst, dst_addr);

    u_int16 src_port = ntohs(po->L4.src);
    u_int16 dst_port = ntohs(po->L4.dst);

    if (pkt_len > 0)
    {
        add_ip_bytes(src_addr, pkt_len);
        add_ip_bytes(dst_addr, pkt_len);
        add_port_bytes(src_port, pkt_len);
        add_port_bytes(dst_port, pkt_len);
    }
}

static void add_ip_bytes(char * ip, uint bytes) 
{
    pthread_mutex_lock(&read_lock);

    if (!ip_stat_holder_ll_head)
    {
        ip_stat_holder_ll_head = create_ip_stat(ip, bytes);
    }
    else
    {
        struct ip_stat_holder * it;

        for (it = ip_stat_holder_ll_head; it != NULL; it = it->next)
        {
            if (strncmp(it->ip, ip, MAX_ASCII_ADDR_LEN) == 0)
            {
                it->bytes += bytes;
                break;
            }
            else if (it->next == NULL)
            {
                it->next = create_ip_stat(ip, bytes);
                break;
            }
        }
    }

    pthread_mutex_unlock(&read_lock);
}

static struct ip_stat_holder* create_ip_stat(char * ip, uint bytes)
{
    struct ip_stat_holder * rec = malloc(sizeof(struct ip_stat_holder));
    
    rec->next = NULL;
    rec->ip = malloc(sizeof(char) * MAX_ASCII_ADDR_LEN);
    rec->bytes = bytes;

    strncpy(rec->ip, ip, MAX_ASCII_ADDR_LEN);

    return rec;
}

// note - this is not thread safe, it must be called in another thread context which already has the lock
static void clear_ip_stats()
{
    struct ip_stat_holder * it = ip_stat_holder_ll_head;
    struct ip_stat_holder * tmp;

    while(it)
    {
        tmp = it;
        it = it->next;

        free(tmp->ip);
        free(tmp);
    }

    ip_stat_holder_ll_head = NULL;
}

static void add_port_bytes(uint port, uint bytes) 
{
    pthread_mutex_lock(&read_lock);

    if (!port_stat_holder_ll_head)
    {
        port_stat_holder_ll_head = create_port_stat(port, bytes);
    }
    else
    {
        struct port_stat_holder * it;

        for (it = port_stat_holder_ll_head; it != NULL; it = it->next)
        {
            if (it->port == port)
            {
                it->bytes += bytes;
                break;
            }
            else if (it->next == NULL)
            {
                it->next = create_port_stat(port, bytes);
                break;
            }
        }
    }

    pthread_mutex_unlock(&read_lock);
}

static struct port_stat_holder* create_port_stat(uint port, uint bytes)
{
    struct port_stat_holder * rec = malloc(sizeof(struct port_stat_holder));
    
    rec->next = NULL;
    rec->port = port;
    rec->bytes = bytes;

    return rec;
}

// note - this is not thread safe, it must be called in another thread context which already has the lock
static void clear_port_stats()
{
    struct port_stat_holder * it = port_stat_holder_ll_head;
    struct port_stat_holder * tmp;

    while(it)
    {
        tmp = it;
        it = it->next;

        free(tmp);
    }

    port_stat_holder_ll_head = NULL;
}

static void pthread_exporter(void * arg) 
{
    char * json_buff = malloc(JSON_BUFF_LEN);

    if (!json_buff) {
        USER_MSG("Failed to allocate json buffer\n");
        return;
    }

    while (exporter_enabled == 1)
    {
        int sleepCt;
        for (sleepCt = 0; sleepCt < exporter_delay && exporter_enabled == 1; sleepCt++) {
            sleep(1);
        }

        if (exporter_enabled == 0) {
            break;
        }

        pthread_mutex_lock(&read_lock);

        struct ip_stat_holder * ip_iter = ip_stat_holder_ll_head;
        struct port_stat_holder * port_iter = port_stat_holder_ll_head;

        int hasBoth = ip_iter && port_iter;

        strncpy(json_buff, "{", JSON_BUFF_LEN);

        if (ip_iter)
        {
            strncat(json_buff, "\"ip_traffic\": {", JSON_BUFF_LEN);
            
            int i = 0;
            char numBuff[64];

            while (ip_iter)
            {
                if (i > 0)
                {
                    strncat(json_buff, ",", JSON_BUFF_LEN);
                }

                snprintf(numBuff, 64, "%d", ip_iter->bytes);
                strncat(json_buff, "\"", JSON_BUFF_LEN);
                strncat(json_buff, ip_iter->ip, JSON_BUFF_LEN);
                strncat(json_buff, "\":", JSON_BUFF_LEN);
                strncat(json_buff, numBuff, JSON_BUFF_LEN);

                ip_iter = ip_iter->next;
                i++;
            }

            strncat(json_buff, "}", JSON_BUFF_LEN);
        }

        if (hasBoth)
        {
            strncat(json_buff, ",", JSON_BUFF_LEN);
        }

        if (port_iter)
        {
            strncat(json_buff, "\"port_traffic\": {", JSON_BUFF_LEN);
            
            int i = 0;
            char portBuff[16];
            char bytesBuff[64];

            while (port_iter)
            {
                if (i > 0)
                {
                    strncat(json_buff, ",", JSON_BUFF_LEN);
                }

                snprintf(portBuff, 16, "%d", port_iter->port);
                snprintf(bytesBuff, 64, "%d", port_iter->bytes);

                strncat(json_buff, "\"", JSON_BUFF_LEN);
                strncat(json_buff, portBuff, JSON_BUFF_LEN);
                strncat(json_buff, "\":", JSON_BUFF_LEN);
                strncat(json_buff, bytesBuff, JSON_BUFF_LEN);

                port_iter = port_iter->next;
                i++;
            }

            strncat(json_buff, "}", JSON_BUFF_LEN);
        }

        strncat(json_buff, "}", JSON_BUFF_LEN);

        clear_ip_stats();
        clear_port_stats();

        pthread_mutex_unlock(&read_lock);

        FILE * statFile = fopen("/tmp/tcp_stats.json", "w");

        if (statFile == NULL)
        {
            USER_MSG("Failed to open tcp_stats.json for writing!\n");
        } else {
            fprintf(statFile, "%s", json_buff);
            fclose(statFile);
        }

        USER_MSG("STAT_EXPORTER: Exported stats after collecting for %d seconds\n", exporter_delay);
    }

    free(json_buff);
}


/* EOF */

// vim:ts=3:expandtab

