#include "sbc.h"

#define SBC_DLG_MAX_CNT 2
#define MAX_CALLS 20
#define INVALID_ID -1

pj_caching_pool          cash_pool;      /* Global pool factory */
pjsip_endpoint           *g_endpt;       /* SIP endpoint        */
pjmedia_endpt	    *g_med_endpt;   /* Media endpoint.		*/

int next_call_id = 0;		/**< Next call id to use*/
pj_mutex_t		*mutex;	    /**< Mutex protection for this data	*/
unsigned		 mutex_nesting_level; /**< Mutex nesting level.	*/
pj_thread_t		*mutex_owner; /**< Mutex owner.			*/

char *visible_nick[2] = {"<sip:vlbrazhnikov@10.25.72.40:7779>", "<sip:vlbrazhnikov@10.25.72.60:8779>"};

PJ_INLINE(void) PJCUSTOM_LOCK()
{
    pj_mutex_lock(mutex);
    mutex_owner = pj_thread_this();
    ++mutex_nesting_level;
}

PJ_INLINE(void) PJCUSTOM_UNLOCK()
{
    if (--mutex_nesting_level == 0)
	mutex_owner = NULL;
    pj_mutex_unlock(mutex);
}

PJ_INLINE(pj_bool_t) PJCUSTOM_LOCK_IS_LOCKED()
{
    return mutex_owner == pj_thread_this();
}



sbc_data *sbc_var = NULL;               // указатель на глобальный массив, содержащий 
                                        // сведения о сессиях и транспортном уровне каждого 
                                        // вызова, а также выдленный индекс call_id      

static vector call_id_table;

dlg_addr_data *dlg_addresses = NULL;


/* Init PJSIP module to be registered by application to handle
 * incoming requests outside any dialogs/transactions
 */
static pjsip_module mod_sbc =
{
    NULL, NULL,                 /* prev, next.      */
    { "mini-sbc", 10 },         /* Name.            */
    -1,                         /* Id           */
    PJSIP_MOD_PRIORITY_APPLICATION, /* Priority         */
    NULL,                       /* load()           */
    NULL,                       /* start()          */
    NULL,                       /* stop()           */
    NULL,                       /* unload()         */
    &on_rx_request,             /* &on_rx_request()      */
    &on_rx_response,            /* &on_rx_response()     */
    NULL,                       /* on_tx_request.       */
    NULL,                       /* &on_tx_response()     */
    &on_tsx_state,              /* &on_tsx_state()       */
};

/* The module for logging messages. */
static pjsip_module msg_logger = 
{
    NULL, NULL,                 /* prev, next.      */
    { "mod-msg-log", 13 },      /* Name.        */
    -1,                         /* Id           */
    PJSIP_MOD_PRIORITY_TRANSPORT_LAYER-1,/* Priority            */
    NULL,                       /* load()       */
    NULL,                       /* start()      */
    NULL,                       /* stop()       */
    NULL,                       /* unload()     */
    &logging_on_rx_msg,         /* on_rx_request()  */
    &logging_on_rx_msg,         /* on_rx_response() */
    &logging_on_tx_msg,         /* on_tx_request.   */
    &logging_on_tx_msg,         /* on_tx_response() */
    NULL,                       /* on_tsx_state()   */
};

int 
main()
{
    pj_status_t status; 

    /* init application */
    status = main_init();
    if (status != PJ_SUCCESS)
    {
        sbc_perror(THIS_FILE, "Error in main_init()", status);
        return PJ_FALSE;
    }

    PJ_LOG(3, (THIS_FILE, "Press: Cntrl+C for quit\n"));

    /* Loop */
    while(1)
    {
        pj_time_val timeout = {0, TIMEOUT_EVENTS_MS};
        status = pjsip_endpt_handle_events(g_endpt, &timeout);
        if (status != PJ_SUCCESS)
        {
            sbc_perror(THIS_FILE, "Error in handle_events()", status);
            break;
        }
    }

    sbc_destroy();

    return status;
}

static pj_status_t main_init(void)
{
    pj_status_t status; 
    pj_pool_t *pool = NULL;

    sbc_var = (sbc_data*)malloc(sizeof(sbc_data) * SBC_DLG_MAX_CNT);
   
    vector_init(&call_id_table);

    status = address_init();
    if (status != PJ_SUCCESS)
        sbc_perror(THIS_FILE, "Error in address_init()",status);

    status = sbc_init();
    if (status != PJ_SUCCESS)
        sbc_perror(THIS_FILE, "Error in sbc_init()", status);

    status = sbc_global_endpt_create();
    if (status != PJ_SUCCESS)
        sbc_perror(THIS_FILE, "Error in global_endpt_create()", status);

    status = sbc_hidden_udp_transport_topology_create();
    if (status != PJ_SUCCESS)
        sbc_perror(THIS_FILE, "Error in sbc_hidden_udp_transport_topology_create()", status);

    /*
     * Init High-Level dialog API
     */
    status = sbc_invite_mod_create();
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    /* Initialize 100rel support */
    status = pjsip_100rel_init_module(g_endpt);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
    /* 
     * Init transaction layer.
     * This will create/initialize transaction hash tables etc.
     */
    status = pjsip_tsx_layer_init_module(g_endpt);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    /* 
     * Initialize UA layer module.
     * This will create/initialize dialog hash tables etc.
     */
    status = pjsip_ua_init_module(g_endpt, NULL );
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    /*
     * Register message logger module.
     */
    status = pjsip_endpt_register_module(g_endpt, &msg_logger);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    /*
     * Register our module to receive incoming requests.
     */
    status = pjsip_endpt_register_module(g_endpt, &mod_sbc);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    status = pjmedia_endpt_create(&cash_pool.factory, NULL, 1, &g_med_endpt);
    /* Create pool. */
    pool = pjmedia_endpt_create_pool(g_med_endpt, "Media pool", 512, 512);	

        /* Create mutex */
    status = pj_mutex_create_recursive(pool, "simple_pjsip", 
				       &mutex);
    if (status != PJ_SUCCESS) {
        pj_log_pop_indent();
        sbc_perror(THIS_FILE, "Unable to create mutex", status);
        /* Destroy mutex */
        if (mutex) {
            pj_mutex_destroy(mutex);
            mutex = NULL;
        }
        return status;
    }

    return status;
}

static pj_status_t address_init(void) {
    dlg_addresses = (dlg_addr_data*)malloc(sizeof(dlg_addr_data) * 2);
    if (!dlg_addresses) {
        perror("malloc");
        return 1;
    }

    strcpy(dlg_addresses[0].uas_addr, "10.25.72.30");
    strcpy(dlg_addresses[0].uac_addr, "10.25.72.40");
    strcpy(dlg_addresses[0].route_addr, "<sip:1133@10.25.72.100:5062>");
    dlg_addresses[0].sbc_port = 7777;
    dlg_addresses[0].rtp_port = 8000;

    strcpy(dlg_addresses[1].uas_addr, "10.25.72.50");
    strcpy(dlg_addresses[1].uac_addr, "10.25.72.60");
    strcpy(dlg_addresses[1].route_addr, "<sip:ilya@10.25.72.27:5060>");
    //strcpy(dlg_addresses[1].route_addr, "<sip:1133@10.25.72.100:5062>");
    dlg_addresses[1].sbc_port = 8777;
    dlg_addresses[1].rtp_port = 9000;

    return PJ_SUCCESS;
}

/* init application data */
static pj_status_t sbc_init(void)
{
    pj_status_t status;

    /* Init PJLIB first */
    status = pj_init();
    if (status != PJ_SUCCESS)
    {
        sbc_perror("PJ_INIT", "Error: ", status);
    }

    pj_log_set_level(5);

    /* Init PJLIB-UTIL */
    status = pjlib_util_init();
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    /* Create a pool factory before allocate memory */
    pj_caching_pool_init(&cash_pool, &pj_pool_factory_default_policy, 0);

    /* Logging success */
    PJ_LOG(3, (THIS_FILE, "initialized successfully\n"));

    return status;
}

/*init global endpoint */
static pj_status_t sbc_global_endpt_create(void)
{
    pj_status_t status;
    const pj_str_t      *hostname; /* hostname for global endpoint */
    const char          *endpt_name;

    /* use hostname for simplicity */

    hostname = pj_gethostname();
    endpt_name = hostname->ptr;

    /* Create the global endpoint */

    status = pjsip_endpt_create(&cash_pool.factory, endpt_name, &g_endpt);
    if (status != PJ_SUCCESS)
    {
        sbc_perror(THIS_FILE, "Global endpt has not created!", status);
    }

    PJ_LOG(3, (THIS_FILE, "Global endpoint has created!\n"));

    return status;
}

static pj_status_t sbc_hidden_udp_transport_topology_create(void)
{
    pj_status_t     status;
    for (int i = 0; i < MAX_DLG_CNT; ++i) {
        pj_sockaddr     addr_a, addr_b;
        pj_int32_t      af = AF;
        pj_str_t        str_sbc_uas = pj_str(dlg_addresses[i].uas_addr);
        pj_str_t        str_sbc_uac = pj_str(dlg_addresses[i].uac_addr);

        /* Socket init */
        status = pj_sockaddr_init(af, &addr_a, &str_sbc_uas, (pj_uint16_t)dlg_addresses[i].sbc_port);
        if (status != PJ_SUCCESS)
        {
            PJ_LOG(3, (THIS_FILE, "Check that sub_net is up\n"));
            sbc_perror(THIS_FILE, "Unable init second socket\n", status);
        }
        
        status = pjsip_udp_transport_start(g_endpt, &addr_a.ipv4, NULL, 1, &sbc_var[i].p_transport_a);
        if (status != PJ_SUCCESS)
        {
            sbc_perror(THIS_FILE, "Unable to start UDP transport", status);
        }

        /*
        * Create sub_network for hide topology
        */
        status = pj_sockaddr_init(af, &addr_b, &str_sbc_uac, (pj_uint16_t)(dlg_addresses[i].sbc_port + 2));
        if (status != PJ_SUCCESS)
        {
            PJ_LOG(3, (THIS_FILE, "Check that sub_net is up\n"));
            sbc_perror(THIS_FILE, "Unable init second socket\n", status);
        }

        status = pjsip_udp_transport_start(g_endpt, &addr_b.ipv4, NULL, 1, &sbc_var[i].p_transport_b);
        if (status != PJ_SUCCESS)
        {
            sbc_perror(THIS_FILE, "Unable to start SECOND UDP transport", status);
        }
    }
    return status;
}

static void sbc_destroy(void)
{
    /* On exit, dump current memory usage: */
    dump_pool_usage(THIS_FILE, &cash_pool);

    /* Deinit pjsip endpoint */
    pjsip_endpt_destroy(g_endpt);
    g_endpt = NULL;

    pj_caching_pool_destroy(&cash_pool);

    /* Shutdown PJLIB */
    pj_shutdown();
}

static pj_status_t sbc_invite_mod_create(void)
{
    pj_status_t status;
    pjsip_inv_callback inv_cb;

    /* Init the callback for INVITE */
    pj_bzero(&inv_cb, sizeof(inv_cb));
    inv_cb.on_state_changed = &call_on_state_changed;
    inv_cb.on_new_session = &call_on_forked;
    inv_cb.on_media_update = &call_on_media_update;

    /* Initialize invite session module:  */
    status = pjsip_inv_usage_init(g_endpt, &inv_cb);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    return status;
}

static pj_bool_t sbc_invite_handler(pjsip_rx_data *rdata)
{
    pj_status_t         status;
    pjsip_tx_data       *p_tdata;
    unsigned            options = 0;
    pj_str_t            local_uri;
    // pj_sockaddr         hostaddr;
    // char                hostip[PJ_INET6_ADDRSTRLEN+2];
    // char                temp[80] = {0};
    pjsip_dialog        *uas_dlg;
    pjsip_tpselector    new_sel;

    

    /* 
     * Respond (statelessly) any non-INVITE requests with 500 
     */

    if (rdata->msg_info.msg->line.req.method.id != PJSIP_INVITE_METHOD) 
    {
        if (rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD) 
        {
            pj_str_t reason = pj_str("Simple UA unable to handle this request");
            pjsip_endpt_respond_stateless( g_endpt, rdata, 500, &reason,
                           NULL, NULL);
        }
        return PJ_TRUE;
    }

    
    PJCUSTOM_LOCK();

    // Find free call slot
    int call_id = alloc_call_id();
    if (call_id == INVALID_ID) {
        pjsip_endpt_respond_stateless(g_endpt, rdata,
                        PJSIP_SC_BUSY_HERE, NULL,
                        NULL, NULL);
        PJ_LOG(2,(THIS_FILE,
            "Unable to accept incoming call (too many calls)"));
        pj_str_t reason = pj_str("Unable to accept incoming call (too many calls)");
        pjsip_endpt_respond_stateless(g_endpt, rdata, 500, &reason,
                           NULL, NULL);
        return PJ_TRUE;
    }

    call_id_data *new_cid = (call_id_data*)malloc(sizeof(call_id_data));
    new_cid->int_call_id = call_id;
    str_malloc(rdata->msg_info.cid->id, &new_cid->sip_call_id_a, rdata->msg_info.cid->id.slen);
    new_cid->sip_call_id_b = NULL;
    vector_pushback(&call_id_table, new_cid);

    

    sbc_data *call = &sbc_var[call_id];

    call->call_id = call_id;
    rdata->endpt_info.mod_data[0] = call;

    /*
     * Send INVITE to other side //add if()
     */

    sbc_request_inv_send(rdata, call_id);    
    
    /* 
     * Verify that we can handle the request 
     */

    status = pjsip_inv_verify_request(rdata, &options, NULL, NULL,
                                    g_endpt, NULL);
    if (status != PJ_SUCCESS) 
    {
        pj_str_t reason = pj_str("Sorry UA can't handle this INVITE");
        pjsip_endpt_respond_stateless( g_endpt, rdata, 500, &reason,
                           NULL, NULL);
        sbc_perror(THIS_FILE, "shutdown application", status);
    }

    /*
     * Save rdata for response?
     */

    status = pjsip_rx_data_clone(rdata, 0, &call->new_rdata);
    if (status != PJ_SUCCESS)
        sbc_perror(THIS_FILE, "FAILED CLONE RX", status);

    /*
     * Get host URI
     */
    
    char tmp[100];
    sprintf(tmp, "<sip:abc@%s:%d>", dlg_addresses[call_id].uas_addr, dlg_addresses[call_id].sbc_port);
    //local_uri = pj_str(/*temp*/"<sip:abc@10.25.72.30:7777>");
    local_uri = pj_str(tmp);
    
    PJ_LOG(3, (THIS_FILE, "UAS IP addr: %s, \n", local_uri));

    /*
     * Create UAS dialog
     */
    status = pjsip_dlg_create_uas_and_inc_lock(pjsip_ua_instance(),
                        rdata, &local_uri, &uas_dlg);
    if (status != PJ_SUCCESS) 
    {
        pjsip_endpt_respond_stateless(g_endpt, rdata, 500, NULL,
                          NULL, NULL);
        sbc_perror(THIS_FILE, "shutdown application", status);
    }
    
    /*
     * Add application module to dialog usages
     */

    status = pjsip_dlg_add_usage(uas_dlg, &mod_sbc, NULL);
    if (status != PJ_SUCCESS)
    {
        pjsip_dlg_dec_lock(uas_dlg);
        sbc_perror(THIS_FILE, "shutdown application", status);
    }
 
    /* 
     * Create invite session, and pass both the UAS dialog
     */

    status = pjsip_inv_create_uas( uas_dlg, rdata, NULL, 0, &call->g_inv);
    pj_assert(status == PJ_SUCCESS);
    if (status != PJ_SUCCESS) 
    {
        pjsip_dlg_dec_lock(uas_dlg);
        sbc_perror(THIS_FILE, "shutdown application", status);
    }

    /*
     * Set UDP transport for UAS
     */

    new_sel.type = PJSIP_TPSELECTOR_TRANSPORT;
    new_sel.u.transport = call->p_transport_a;

    pjsip_tpselector_add_ref(&new_sel);
    status = pjsip_dlg_set_transport(uas_dlg, &new_sel);
    if (status != PJ_SUCCESS)
        sbc_perror(THIS_FILE, "Unable set new transport", status);
    pjsip_tpselector_dec_ref(&new_sel);

    /*
     * Get SDP body
     */ 

    pjsip_rdata_sdp_info *sdp_info;
    sdp_info = pjsip_rdata_get_sdp_info(rdata);

    /*
     * Set local SDP offer / answer for g_inv
     */

    status = pjsip_inv_set_local_sdp(call->g_inv, sdp_info->sdp);
    if (status != PJ_SUCCESS)
        sbc_perror(THIS_FILE, "Error local_SDP\n", status);

    /*
     * Initially first response & send 100 trying
     */

    status = pjsip_inv_initial_answer(call->g_inv, rdata, PJSIP_SC_TRYING, NULL, NULL, &p_tdata);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, PJ_TRUE);


    /* Send the 100 response. */  
    status = pjsip_inv_send_msg(call->g_inv, p_tdata); 
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, PJ_TRUE);

    call->g_inv->mod_data[0] = call;

    PJCUSTOM_UNLOCK();

    return PJ_TRUE;
}

/*
 * SBC routing to other network interface
 */
static pj_bool_t sbc_request_inv_send(pjsip_rx_data *rdata, int call_id)
{
    pj_status_t         status;
    pjsip_tx_data       *p_tdata;
    pjsip_dialog        *uac_dlg = NULL;
    pjsip_tpselector    tp_sel;

    /*
     * Set route to direct for SBC
     */

    pj_str_t            local_uri = pj_str(visible_nick[call_id]);
    pj_str_t            dest_uri = pj_str(dlg_addresses[call_id].route_addr);

    sbc_data *call = (sbc_data*) rdata->endpt_info.mod_data[0];

    /*
     * Add new UDP transport ot TP_SELECTOR
     */

    tp_sel.type = PJSIP_TPSELECTOR_TRANSPORT;
    tp_sel.u.transport = call->p_transport_b;

    pjsip_user_agent *agent = pjsip_ua_instance();
 
    status = pjsip_dlg_create_uac(agent, 
                        &local_uri,
                        &local_uri,
                        &dest_uri,
                        &dest_uri,
                        &uac_dlg);
    if (status != PJ_SUCCESS)
        sbc_perror(THIS_FILE, "Unable create UAC", status);

    pjsip_dlg_inc_lock(uac_dlg);

    /*
     * Bind dialog to a specific transport 
     */

    status = pjsip_dlg_set_transport(uac_dlg, &tp_sel);
    if (status != PJ_SUCCESS)
        sbc_perror(THIS_FILE, "Unable set new transport for UAC", status);

    /*
     * Add application module to dialog usages
     */

    status = pjsip_dlg_add_usage(uac_dlg, &mod_sbc, NULL);
    if (status != PJ_SUCCESS)
    {
        pjsip_dlg_dec_lock(uac_dlg);
        sbc_perror(THIS_FILE, "shutdown application", status);
    }

    /* 
     * Create the INVITE session for B side
     */

    status = pjsip_inv_create_uac(uac_dlg, NULL, 0, &sbc_var[call_id].g_out);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);
    
    /*
     * Get SDP body
     */ 

    pjsip_rdata_sdp_info *sdp_info;
    sdp_info = pjsip_rdata_get_sdp_info(rdata);

    /*
     * Set local SDP offer / answer for g_out
     */

    status = pjsip_inv_set_local_sdp(call->g_out, sdp_info->sdp);
    if (status != PJ_SUCCESS)
        sbc_perror(THIS_FILE, "Error local_SDP\n", status);

    PJCUSTOM_LOCK();

    call_id_data *cid = (call_id_data*) vector_search_by_int_call_id(&call_id_table, call_id);

    if (cid != NULL) {
        if (cid->sip_call_id_b == NULL) {
            str_malloc(uac_dlg->call_id->id, &cid->sip_call_id_b, uac_dlg->call_id->id.slen);
        }
    }

    PJCUSTOM_UNLOCK();

    /*
     * Create INVITE request 
     */

    status = pjsip_inv_invite(call->g_out, &p_tdata);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    /*
     * Send INVITE to B
     */

    status = pjsip_inv_send_msg(call->g_out, p_tdata);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    //sbc_var[call_id].g_out->mod_data[0] = (sbc_data*)&sbc_var[call_id];
    call->g_out->mod_data[0] = call;
    return PJ_TRUE;
}

/*
 * SBC send response to B side
 */
static pj_bool_t sbc_response_code_send(pjsip_rx_data * rdata, unsigned code, int call_id)
{
    pj_status_t                 status;
    pjsip_tx_data               *p_tdata;
    pjsip_rdata_sdp_info        *sdp_info_b;
    pjsip_msg_body              *p_body;
    pj_timer_entry              *ack_timer;
    /*
     * 1) get dlg from rdata
     * 2) set new transport for dlg
     * 3) get invite session from tsx
       4) create response for session
       5) send response for session
     */
    if (sbc_var[call_id].g_inv->invite_tsx && sbc_var[call_id].g_inv->state != PJSIP_INV_STATE_DISCONNECTED) {
        status = pjsip_inv_initial_answer(sbc_var[call_id].g_inv, sbc_var[call_id].new_rdata, code, NULL, NULL, &p_tdata);
        if (status != PJ_SUCCESS)
            sbc_perror(THIS_FILE, "Error in pjsip_inv_initial_answer", status);

        if (code == PJSIP_SC_OK)
        {
            sdp_info_b = pjsip_rdata_get_sdp_info(rdata);
            status = pjsip_create_sdp_body(p_tdata->pool, 
                                    sdp_info_b->sdp,
                                    &p_body);
            if (status != PJ_SUCCESS)
                sbc_perror(THIS_FILE, "Error in create_sdp_body", status);

            /* set new body */
            pj_size_t size = 400;
            char buf[size];
            p_tdata->msg->body = p_body;
            p_tdata->msg->body->print_body(p_tdata->msg->body, buf, size);
            PJ_LOG(3, (THIS_FILE, "%s, len: %lu", buf, size));

            /*
            * Free cloned rdata for UAS
            */
            status = pjsip_rx_data_free_cloned(sbc_var[call_id].new_rdata);
            if (status != PJ_SUCCESS)
                sbc_perror(THIS_FILE, "RX not FREE!", status);
        }

        // Send response to A side
        status = pjsip_inv_send_msg(sbc_var[call_id].g_inv, p_tdata);
    }
    return PJ_TRUE;
}

/* 
 * SBC recive incoming request from A side and handling it
 */
static pj_bool_t on_rx_request( pjsip_rx_data *rdata )
{
    switch (rdata->msg_info.msg->line.req.method.id)
    {
        case PJSIP_INVITE_METHOD:
            sbc_invite_handler(rdata);
            break;
        default:
            PJ_LOG(3, (THIS_FILE, "default \n"));
            break;
    }
    return PJ_TRUE;
}

/*
 * Recive response from B side
 */
static pj_bool_t on_rx_response( pjsip_rx_data *rdata)
{
    unsigned        response_code = rdata->msg_info.msg->line.status.code;
    PJ_LOG(3, (THIS_FILE, "Should check rdata in on_rx_response!\n"));
    
    PJCUSTOM_LOCK();

    int call_id = -1;
    char *sip_call_id = (char*)malloc(sizeof(char)*(rdata->msg_info.cid->id.slen + 1));
    strncpy(sip_call_id, rdata->msg_info.cid->id.ptr, rdata->msg_info.cid->id.slen);
    sip_call_id[rdata->msg_info.cid->id.slen] = '\0';

    call_id_data *cid = (call_id_data*) vector_search_by_sip_call_id(&call_id_table, sip_call_id);

    if (cid != NULL) {
        call_id = cid->int_call_id;
    }

    free(sip_call_id);
    sip_call_id = NULL;

    PJCUSTOM_UNLOCK();

    if (call_id != -1) {
        if (sbc_var[call_id].g_inv != NULL)
        {
            switch(response_code)
            {
                case PJSIP_SC_RINGING:
                    sbc_response_code_send(rdata, PJSIP_SC_RINGING, call_id);
                    break;

                case PJSIP_SC_OK:
                    sbc_response_code_send(rdata, PJSIP_SC_OK, call_id);
                    break;
                case PJSIP_SC_DECLINE:
                    sbc_response_code_send(rdata, PJSIP_SC_DECLINE, call_id);
                    break;
                default:
                    PJ_LOG(3, (THIS_FILE, "response not found\n"));
            }
        }
        else
        {
            PJ_LOG(6, (THIS_FILE, "session A<->SBC already TERMINATED\n"));
            return PJ_FALSE;
        }
    }
    else {
        PJ_LOG(3, (THIS_FILE, "Invalid call_id\n"));
    }
    return PJ_TRUE;
}

/*
 * Transaction state
 */
static void on_tsx_state( pjsip_transaction *tsx, pjsip_event *event)
{
    PJ_UNUSED_ARG(event);
    pj_assert(event->type == PJSIP_EVENT_TSX_STATE);
    PJ_LOG(3, (THIS_FILE, "Transaction %s: state changed to %s",
                            tsx->obj_name, pjsip_tsx_state_str(tsx->state)));
}

/*
 * Callback when INVITE session state has changed.
 * After invite session module is initialized.
 * If invite session has been disconnected, we can quit the application.
 */
static void call_on_state_changed( pjsip_inv_session *inv, pjsip_event *e)
{
    pj_status_t         status;
    pjsip_tx_data       *p_tdata;
    PJ_UNUSED_ARG(e);
    sbc_data *call = (sbc_data*)inv->mod_data[0];

    if (inv->state == PJSIP_INV_STATE_DISCONNECTED) 
    {
        PJ_LOG(3,(THIS_FILE, "Call DISCONNECTED [reason=%d (%s)]", 
                    inv->cause,
                    pjsip_get_status_text(inv->cause)->ptr));

        PJ_LOG(6, (THIS_FILE, "INV role: %s", inv->role));

        if (inv == sbc_var[call->call_id].g_inv && sbc_var[call->call_id].g_out) 
        {
            PJ_LOG(3, (THIS_FILE, "A sent BYE SBC, SBC sent BYE B"));

            status = pjsip_inv_end_session(sbc_var[call->call_id].g_out, inv->cause, NULL, &p_tdata);
            if (status != PJ_SUCCESS)
                sbc_perror(THIS_FILE, "Error end_session()", status);

            status = pjsip_inv_send_msg(sbc_var[call->call_id].g_out, p_tdata);
            if (status != PJ_SUCCESS)
                sbc_perror(THIS_FILE, "Error sent BYE to B", status);

           /*  do
            {
                status = pjsip_inv_dec_ref(sbc_var[call->call_id].g_inv);
            }
            while (status != PJ_EGONE); */
        }
        else if (inv == sbc_var[call->call_id].g_out && sbc_var[call->call_id].g_inv) {
            PJ_LOG(3, (THIS_FILE, "B sent BYE SBC, SBC sent BYE A"));

            status = pjsip_inv_end_session(sbc_var[call->call_id].g_inv, inv->cause, NULL, &p_tdata);
            if (status != PJ_SUCCESS)
                sbc_perror(THIS_FILE, "Error end_session()", status);

            status = pjsip_inv_send_msg(sbc_var[call->call_id].g_inv, p_tdata);
            if (status != PJ_SUCCESS)
                sbc_perror(THIS_FILE, "Error sent BYE to A", status);
        }

        /* clean inv session */
        /* do
        {
            status = pjsip_inv_dec_ref(sbc_var[call->call_id].g_out);
        }
        while (status != PJ_EGONE); */

       
        int idx = vector_search_index_by_int_call_id(&call_id_table, call->call_id);
        if (idx != INVALID_ID && idx < MAX_DLG_CNT) {
            vector_delete(&call_id_table, idx);
        }
        free_call_id(call->call_id);
    }

    PJ_LOG(3,(THIS_FILE, "Call state changed to %s", pjsip_inv_state_name(inv->state)));
}

/* This callback is called when dialog has forked. */
static void call_on_forked(pjsip_inv_session *inv, pjsip_event *e)
{
    /* To be done... */
    PJ_UNUSED_ARG(inv);
    PJ_UNUSED_ARG(e);
}

static void call_on_media_update( pjsip_inv_session *inv, pj_status_t status)
{
    sbc_data* call = (sbc_data*)inv->mod_data[0];
   
    if (status != PJ_SUCCESS) {

        sbc_perror(THIS_FILE, "SDP negotiation has failed", status);

        /* Here we should disconnect call if we're not in the middle 
        * of initializing an UAS dialog and if this is not a re-INVITE.
        */
        return;
    }
}

/* Notification on outgoing messages */
static pj_status_t logging_on_tx_msg(pjsip_tx_data *tdata)
{
    
    /* Important note:
     *  tp_info field is only valid after outgoing messages has passed
     *  transport layer. So don't try to access tp_info when the module
     *  has lower priority than transport layer.
     */

    PJ_LOG(4,("-LOG-", "TX %d bytes %s to %s %s:%d:\n"
             "%.*s\n"
             "--end msg--",
             (tdata->buf.cur - tdata->buf.start),
             pjsip_tx_data_get_info(tdata),
             tdata->tp_info.transport->type_name,
             tdata->tp_info.dst_name,
             tdata->tp_info.dst_port,
             (int)(tdata->buf.cur - tdata->buf.start),
             tdata->buf.start));

    /* Always return success, otherwise message will not get sent! */
    return PJ_SUCCESS;
}

/* Notification on incoming messages */
static pj_bool_t logging_on_rx_msg(pjsip_rx_data *rdata)
{
    PJ_LOG(4,("-LOG-", "RX %d bytes %s from %s %s:%d:\n"
             "%.*s\n"
             "--end msg--",
             rdata->msg_info.len,
             pjsip_rx_data_get_info(rdata),
             rdata->tp_info.transport->type_name,
             rdata->pkt_info.src_name,
             rdata->pkt_info.src_port,
             (int)rdata->msg_info.len,
             rdata->msg_info.msg_buf));

    /* Always return false, otherwise messages will not get processed! */
    return PJ_FALSE;
}

static void sbc_perror(const char *sender, const char *title, 
                pj_status_t status)
{
    char errmsg[PJ_ERR_MSG_SIZE];

    pj_strerror(status, errmsg, sizeof(errmsg));
    PJ_LOG(1,(sender, "%s: %s [code=%d]", title, errmsg, status));
    sbc_destroy();
}

/* Dump memory pool usage. */
static void dump_pool_usage( const char *app_name, pj_caching_pool *cp )
{
#if !defined(PJ_HAS_POOL_ALT_API) || PJ_HAS_POOL_ALT_API==0
    pj_pool_t   *p;
    pj_size_t    total_alloc = 0;
    pj_size_t    total_used = 0;

    /* Accumulate memory usage in active list. */
    p = (pj_pool_t*)cp->used_list.next;
    while (p != (pj_pool_t*) &cp->used_list) {
    total_alloc += pj_pool_get_capacity(p);
    total_used += pj_pool_get_used_size(p);
    p = p->next;
    }

    PJ_LOG(3, (app_name, "Total pool memory allocated=%d KB, used=%d KB",
           total_alloc / 1000,
           total_used / 1000));
#endif
}

/* Allocate one call id */
static int alloc_call_id(void)
{
    int cid;

    /* New algorithm: round-robin */
    if (next_call_id >= MAX_DLG_CNT || next_call_id < 0) {
	    next_call_id = 0;
    }

    for ( cid = next_call_id; cid < MAX_DLG_CNT; ++cid) {
        //if (calls[cid].inv == NULL && calls[cid].async_call.dlg == NULL) {
        if (sbc_var[cid].is_busy == PJ_FALSE) {
            ++next_call_id;
            return cid;
        }
    }

    for ( cid = 0; cid < next_call_id; ++cid) {
        //if (calls[cid].inv == NULL && calls[cid].async_call.dlg == NULL) {
        if (sbc_var[cid].is_busy == PJ_FALSE) {
            ++next_call_id;
            return cid;
        }
    }

    return INVALID_ID;
}

static void free_call_id(int call_id) {
    sbc_var[call_id].is_busy = PJ_FALSE;
    sbc_var[call_id].g_inv = NULL;
    PJ_LOG(6, (THIS_FILE, "g_inv is destroyed\n"));
    sbc_var[call_id].g_out = NULL;
    PJ_LOG(6, (THIS_FILE, "g_out is destroyed\n"));
    sbc_var[call_id].call_id = INVALID_ID;    
}

void vector_init(vector *v)
{
    //initialize the capacity and allocate the memory
    v->capacity = VECTOR_INIT_CAPACITY;
    v->size = 0;
    v->items = malloc(sizeof(void *) * v->capacity);
}

void* vector_search_by_sip_call_id(vector *v, const char *sip_cid) 
{
    for (int i = 0; i < vector_size(v); ++i) {
        call_id_data *cid = (call_id_data*)vector_get(v, i);
        if (cid->sip_call_id_a && !strcmp(cid->sip_call_id_a, sip_cid) ||
            cid->sip_call_id_b && !strcmp(cid->sip_call_id_b, sip_cid)) {
            return cid;
        }
    }
    return NULL;
}

void* vector_search_by_int_call_id(vector *v, int i_cid) 
{
    for (int i = 0; i < vector_size(v); ++i) {
        call_id_data *cid = (call_id_data*)vector_get(v, i);
        if (cid->int_call_id == i_cid) {
            return cid;
        }
    }
    return NULL;
}

int vector_search_index_by_int_call_id(vector *v, int i_cid) 
{
    for (int i = 0; i < vector_size(v); ++i) {
        call_id_data *cid = (call_id_data*)vector_get(v, i);
        if (cid->int_call_id == i_cid) {
            return i;
        }
    }
    return INVALID_ID;
}

static void str_malloc(pj_str_t src, char **dst, size_t len) {
    *dst = (char*)malloc(sizeof(char) * (src.slen+1));
    strncpy(*dst, src.ptr, len);
    (*dst)[src.slen] = '\0';
}
