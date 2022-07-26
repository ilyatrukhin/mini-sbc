#ifndef __SBC_H__
#define __SBC_H__

#include <pjlib.h>
#include <pjlib-util.h>
#include <pjmedia.h>
#include <pjmedia-codec.h>
#include <pjsip.h>
#include <pjsip_simple.h>
#include <pjsip_ua.h>

#include "vector/vector.h"

#define THIS_FILE           "SBC_mini"

#define MAX_DLG_CNT 2


/* UDP transport settings*/
#define AF                  pj_AF_INET()
#define RTP_PORT            4020
#define PORT2               8888
#define MAX_MEDIA_CNT       1        /* Media count, set to 1 for aud 2 for aud & video */
#define TIMEOUT_EVENTS_MS   5000



struct dlg_addr_data {
    char uas_addr[16];
    char uac_addr[16];
    char route_addr[40];
    pj_uint16_t sbc_port;
    pj_uint16_t rtp_port;
};

typedef struct sbc_data { 
    /* Call variables */
    pjsip_inv_session        *g_inv;         /* Current invite session A <-> SBC */
    pjsip_inv_session        *g_out;         /* SBC <-> B side */
    pjsip_transport          *p_transport_a; 
    pjsip_transport          *p_transport_b;
    pjsip_rx_data            *new_rdata;
    int                      call_id;
    pj_bool_t                is_busy;
} sbc_data;

typedef struct call_id_data {
    char *sip_call_id_a;
    char *sip_call_id_b;
    int int_call_id;
} call_id_data;


typedef struct dlg_addr_data dlg_addr_data;

/* for all application */

/* define prototypes of func */

static void sbc_perror(const char *sender, const char *title, pj_status_t status);
static void sbc_destroy(void);

static void call_on_state_changed( pjsip_inv_session *inv, pjsip_event *e);
static void call_on_forked(pjsip_inv_session *inv, pjsip_event *e);
static void call_on_media_update( pjsip_inv_session *inv, pj_status_t status);

static pj_status_t main_init(void);
static pj_status_t address_init(void);
static pj_status_t sbc_init(void);
static pj_status_t sbc_global_endpt_create(void);
static pj_status_t sbc_hidden_udp_transport_topology_create(void);
static pj_status_t sbc_invite_mod_create(void);


/* Handler for INVITE request */
static pj_bool_t sbc_invite_handler(pjsip_rx_data *rdata);
static pj_bool_t sbc_request_inv_send(pjsip_rx_data *rdata, int call_id);
static pj_bool_t sbc_response_code_send(pjsip_rx_data *rdata, unsigned code, int call_id);

/* Logging */
static pj_status_t logging_on_tx_msg(pjsip_tx_data *tdata);
static pj_bool_t logging_on_rx_msg(pjsip_rx_data *rdata);
static void on_tsx_state( pjsip_transaction *tsx, pjsip_event *event);


/* Callback to be called to handle incoming requests outside dialogs: */
static pj_bool_t on_rx_request( pjsip_rx_data *rdata );
static pj_bool_t on_rx_response( pjsip_rx_data *rdata);

/* Dump memory pool usage. */
static void dump_pool_usage( const char *app_name, pj_caching_pool *cp );

void vector_init(vector *v);

void* vector_search_by_sip_call_id(vector *v, const char *sip_cid);
void* vector_search_by_int_call_id(vector *v, int i_cid);
int vector_search_index_by_int_call_id(vector *v, int i_cid);

static void str_malloc(pj_str_t src, char **dst, size_t len);

static int alloc_call_id(void);
static void free_call_id(int call_id);

#endif