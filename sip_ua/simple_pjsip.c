/*
 * Usage:
 *  - To make outgoing call, start simpleua with the URL of remote
 *    destination to contact.
 *    E.g.:
 *	 simpleua sip:user@remote [dst URI] [local IP] [SIP port] [RTP port]
 *
 *  - Incoming calls will automatically be answered with 180, then 200.
 *
 * This program does not disconnect call.
 *
 * This program will quit once it has completed a single call.
 */

/* Include all headers. */
#include <pjsip.h>
#include <pjmedia.h>
#include <pjmedia-codec.h>
#include <pjsip_ua.h>
#include <pjsip_simple.h>
#include <pjlib-util.h>
#include <pjlib.h>

/* For logging purpose. */
#define THIS_FILE   "simpleua.c"

#include "util.h"


/* Settings */
#define AF		pj_AF_INET() /* Change to pj_AF_INET6() for IPv6.
				      * PJ_HAS_IPV6 must be enabled and
				      * your system must support IPv6.  */

#define SIP_PORT	5070	     /* Listening SIP port		*/
#define RTP_PORT	4000	     /* RTP port			*/


#define MAX_MEDIA_CNT	2	     /* Media count, set to 1 for audio
				      * only or 2 for audio and video	*/

/*
 * Static variables.
 */

static pj_bool_t	     g_complete;    /* Quit flag.		*/
static pjsip_endpoint	    *g_endpt;	    /* SIP endpoint.		*/
static pj_caching_pool	     cp;	    /* Global pool factory.	*/

static pjmedia_endpt	    *g_med_endpt;   /* Media endpoint.		*/

static pjmedia_transport_info g_med_tpinfo[MAX_MEDIA_CNT]; 
					    /* Socket info for media	*/
static pjmedia_transport    *g_med_transport[MAX_MEDIA_CNT];
					    /* Media stream transport	*/
static pjmedia_sock_info     g_sock_info[MAX_MEDIA_CNT];  
					    /* Socket info array	*/

/* Call variables: */
static pjsip_inv_session    *g_inv;	    /* Current invite session.	*/
static pjmedia_stream       *g_med_stream;  /* Call's audio stream.	*/
static pjmedia_snd_port	    *g_snd_port;    /* Sound device.		*/


/*
 * Prototypes:
 */


/* Callback to be called when invite session's state has changed: */
static void call_on_state_changed( pjsip_inv_session *inv, 
				   pjsip_event *e);

/* Callback to be called when dialog has forked: */
static void call_on_forked(pjsip_inv_session *inv, pjsip_event *e);

/* Callback to be called to handle incoming requests outside dialogs: */
static pj_bool_t on_rx_request( pjsip_rx_data *rdata );

static pj_bool_t on_rx_response( pjsip_rx_data *rdata );



/* This is a PJSIP module to be registered by application to handle
 * incoming requests outside any dialogs/transactions. The main purpose
 * here is to handle incoming INVITE request message, where we will
 * create a dialog and INVITE session for it.
 */
static pjsip_module mod_simpleua =
{
    NULL, NULL,			    /* prev, next.		*/
    { "mod-simpleua", 12 },	    /* Name.			*/
    -1,				    /* Id			*/
    PJSIP_MOD_PRIORITY_APPLICATION, /* Priority			*/
    NULL,			    /* load()			*/
    NULL,			    /* start()			*/
    NULL,			    /* stop()			*/
    NULL,			    /* unload()			*/
    &on_rx_request,		    /* on_rx_request()		*/
    &on_rx_response,	  /* on_rx_response()		*/
    NULL,			    /* on_tx_request.		*/
    NULL,			    /* on_tx_response()		*/
    NULL,			    /* on_tsx_state()		*/
};


/* Notification on incoming messages */
static pj_bool_t logging_on_rx_msg(pjsip_rx_data *rdata)
{
    PJ_LOG(4,(THIS_FILE, "RX %d bytes %s from %s %s:%d:\n"
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

/* Notification on outgoing messages */
static pj_status_t logging_on_tx_msg(pjsip_tx_data *tdata)
{
    
    /* Important note:
     *	tp_info field is only valid after outgoing messages has passed
     *	transport layer. So don't try to access tp_info when the module
     *	has lower priority than transport layer.
     */

    PJ_LOG(4,(THIS_FILE, "TX %d bytes %s to %s %s:%d:\n"
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

/* The module instance. */
static pjsip_module msg_logger = 
{
    NULL, NULL,				/* prev, next.		*/
    { "mod-msg-log", 13 },		/* Name.		*/
    -1,					/* Id			*/
    PJSIP_MOD_PRIORITY_TRANSPORT_LAYER-1,/* Priority	        */
    NULL,				/* load()		*/
    NULL,				/* start()		*/
    NULL,				/* stop()		*/
    NULL,				/* unload()		*/
    &logging_on_rx_msg,			/* on_rx_request()	*/
    &logging_on_rx_msg,			/* on_rx_response()	*/
    &logging_on_tx_msg,			/* on_tx_request.	*/
    &logging_on_tx_msg,			/* on_tx_response()	*/
    NULL,				/* on_tsx_state()	*/

};


/*
 * main()
 *
 * If called with argument, treat argument as SIP URL to be called.
 * Otherwise wait for incoming calls.
 */
int main(int argc, char *argv[])
{
	int sip_port = SIP_PORT;
    pj_pool_t *pool = NULL;
    pj_status_t status;
    unsigned i;

    /* Must init PJLIB first: */
    status = pj_init();
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    pj_log_set_level(5);

    /* Then init PJLIB-UTIL: */
    status = pjlib_util_init();
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);


    /* Must create a pool factory before we can allocate any memory. */
    pj_caching_pool_init(&cp, &pj_pool_factory_default_policy, 0);


    /* Create global endpoint: */
    {
	const pj_str_t *hostname;
	const char *endpt_name;

	/* Endpoint MUST be assigned a globally unique name.
	 * The name will be used as the hostname in Warning header.
	 */

	/* For this implementation, we'll use hostname for simplicity */
	hostname = pj_gethostname();
	endpt_name = hostname->ptr;

	/* Create the endpoint: */

	status = pjsip_endpt_create(&cp.factory, endpt_name, 
				    &g_endpt);
	PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);
    }


    /* 
     * Add UDP transport, with hard-coded port 
     * Alternatively, application can use pjsip_udp_transport_attach() to
     * start UDP transport, if it already has an UDP socket (e.g. after it
     * resolves the address with STUN).
     */
    {
	pj_sockaddr addr;
	int af = AF;
	if (argc > 2){
		pj_str_t cp = pj_str(argv[2]);
		if (argc > 3) {
			sip_port = atoi(argv[3]);
		}
		pj_sockaddr_init(af, &addr, &cp, (pj_uint16_t)sip_port);
	}
	else {
		pj_sockaddr_init(af, &addr, NULL, (pj_uint16_t)sip_port);
	}
	
	if (af == pj_AF_INET()) {
	    status = pjsip_udp_transport_start( g_endpt, &addr.ipv4, NULL, 
						1, NULL);
	} else if (af == pj_AF_INET6()) {
	    status = pjsip_udp_transport_start6(g_endpt, &addr.ipv6, NULL,
						1, NULL);
	} else {
	    status = PJ_EAFNOTSUP;
	}

	if (status != PJ_SUCCESS) {
	    app_perror(THIS_FILE, "Unable to start UDP transport", status);
	    return 1;
	}
    }


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
    status = pjsip_ua_init_module( g_endpt, NULL );
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);


    /* 
     * Init invite session module.
     * The invite session module initialization takes additional argument,
     * i.e. a structure containing callbacks to be called on specific
     * occurence of events.
     *
     * The on_state_changed and on_new_session callbacks are mandatory.
     * Application must supply the callback function.
     *
     * We use on_media_update() callback in this application to start
     * media transmission.
     */
    {
	pjsip_inv_callback inv_cb;

	/* Init the callback for INVITE session: */
	pj_bzero(&inv_cb, sizeof(inv_cb));
	inv_cb.on_state_changed = &call_on_state_changed;
	inv_cb.on_new_session = &call_on_forked;

	/* Initialize invite session module:  */
	status = pjsip_inv_usage_init(g_endpt, &inv_cb);
	PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);
    }

    /* Initialize 100rel support */
    status = pjsip_100rel_init_module(g_endpt);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

    /*
     * Register our module to receive incoming requests.
     */
    status = pjsip_endpt_register_module( g_endpt, &mod_simpleua);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    /*
     * Register message logger module.
     */
    status = pjsip_endpt_register_module( g_endpt, &msg_logger);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);


    /* 
     * Initialize media endpoint.
     * This will implicitly initialize PJMEDIA too.
     */
#if PJ_HAS_THREADS
    status = pjmedia_endpt_create(&cp.factory, NULL, 1, &g_med_endpt);
#else
    status = pjmedia_endpt_create(&cp.factory, 
				  pjsip_endpt_get_ioqueue(g_endpt), 
				  0, &g_med_endpt);
#endif
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    /* Create pool. */
    pool = pjmedia_endpt_create_pool(g_med_endpt, "Media pool", 512, 512);	

    /* 
     * Add PCMA/PCMU codec to the media endpoint. 
     */
#if defined(PJMEDIA_HAS_G711_CODEC) && PJMEDIA_HAS_G711_CODEC!=0
    status = pjmedia_codec_g711_init(g_med_endpt);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);
#endif


    
    /* Create event manager */
    status = pjmedia_event_mgr_create(pool, 0, NULL);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

    /* 
     * Create media transport used to send/receive RTP/RTCP socket.
     * One media transport is needed for each call. Application may
     * opt to re-use the same media transport for subsequent calls.
     */
	int rtp_port = RTP_PORT;
	if (argc > 4) {
		rtp_port = atoi(argv[4]);
	}
    for (i = 0; i < PJ_ARRAY_SIZE(g_med_transport); ++i) {
	status = pjmedia_transport_udp_create3(g_med_endpt, AF, NULL, NULL, 
					       rtp_port + i*2, 0, 
					       &g_med_transport[i]);
	if (status != PJ_SUCCESS) {
	    app_perror(THIS_FILE, "Unable to create media transport", status);
	    return 1;
	}

	/* 
	 * Get socket info (address, port) of the media transport. We will
	 * need this info to create SDP (i.e. the address and port info in
	 * the SDP).
	 */
	pjmedia_transport_info_init(&g_med_tpinfo[i]);
	pjmedia_transport_get_info(g_med_transport[i], &g_med_tpinfo[i]);

	pj_memcpy(&g_sock_info[i], &g_med_tpinfo[i].sock_info,
		  sizeof(pjmedia_sock_info));
    }

    /*
     * If URL is specified, then make call immediately.
     */
    if (argc > 1) {
	pj_sockaddr hostaddr;
	char hostip[PJ_INET6_ADDRSTRLEN+2];
	char temp[80];
	pj_str_t dst_uri = pj_str(argv[1]);
	pj_str_t local_uri;
	pjsip_dialog *dlg;
	pjmedia_sdp_session *local_sdp;
	pjsip_tx_data *tdata;

	if (pj_gethostip(AF, &hostaddr) != PJ_SUCCESS) {
	    app_perror(THIS_FILE, "Unable to retrieve local host IP", status);
	    return 1;
	}
	pj_sockaddr_print(&hostaddr, hostip, sizeof(hostip), 2);

	pj_ansi_sprintf(temp, "<sip:simpleuac@%s:%d>", 
			argv[2], sip_port);
	local_uri = pj_str(temp);

	/* Create UAC dialog */
	status = pjsip_dlg_create_uac( pjsip_ua_instance(), 
				       &local_uri,  /* local URI */
				       &local_uri,  /* local Contact */
				       &dst_uri,    /* remote URI */
				       &dst_uri,    /* remote target */
				       &dlg);	    /* dialog */
	if (status != PJ_SUCCESS) {
	    app_perror(THIS_FILE, "Unable to create UAC dialog", status);
	    return 1;
	}

	/* Get the SDP body to be put in the outgoing INVITE, by asking
	 * media endpoint to create one for us.
	 */
	status = pjmedia_endpt_create_sdp( g_med_endpt,	    /* the media endpt	*/
					   dlg->pool,	    /* pool.		*/
					   MAX_MEDIA_CNT,   /* # of streams	*/
					   g_sock_info,     /* RTP sock info	*/
					   &local_sdp);	    /* the SDP result	*/
	PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

	/* Create the INVITE session, and pass the SDP returned earlier
	 * as the session's initial capability.
	 */
	status = pjsip_inv_create_uac( dlg, local_sdp, 0, &g_inv);
	PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

	/* Create initial INVITE request.
	 * This INVITE request will contain a perfectly good request and 
	 * an SDP body as well.
	 */
	status = pjsip_inv_invite(g_inv, &tdata);
	PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);

	/* Send initial INVITE request. 
	 * From now on, the invite session's state will be reported to us
	 * via the invite session callbacks.
	 */
	status = pjsip_inv_send_msg(g_inv, tdata);
	PJ_ASSERT_RETURN(status == PJ_SUCCESS, 1);


    } else {

	/* No URL to make call to */

	PJ_LOG(3,(THIS_FILE, "Ready to accept incoming calls..."));
    }


    /* Loop until one call is completed */
    for (;!g_complete;) {
	pj_time_val timeout = {0, 10};
	pjsip_endpt_handle_events(g_endpt, &timeout);
    }

    /* On exit, dump current memory usage: */
    dump_pool_usage(THIS_FILE, &cp);

    /* Destroy audio ports. Destroy the audio port first
     * before the stream since the audio port has threads
     * that get/put frames to the stream.
     */


    /* Destroy media transports */
    for (i = 0; i < MAX_MEDIA_CNT; ++i) {
	if (g_med_transport[i])
	    pjmedia_transport_close(g_med_transport[i]);
    }

    /* Destroy event manager */
    pjmedia_event_mgr_destroy(NULL); 

    /* Deinit pjmedia endpoint */
    if (g_med_endpt)
	pjmedia_endpt_destroy(g_med_endpt);

    /* Deinit pjsip endpoint */
    if (g_endpt)
	pjsip_endpt_destroy(g_endpt);

    /* Release pool */
    if (pool)
	pj_pool_release(pool);

    return 0;
}



/*
 * Callback when INVITE session state has changed.
 * This callback is registered when the invite session module is initialized.
 * We mostly want to know when the invite session has been disconnected,
 * so that we can quit the application.
 */
static void call_on_state_changed( pjsip_inv_session *inv, 
				   pjsip_event *e)
{
    PJ_UNUSED_ARG(e);

    if (inv->state == PJSIP_INV_STATE_DISCONNECTED) {

	PJ_LOG(3,(THIS_FILE, "Call DISCONNECTED [reason=%d (%s)]", 
		  inv->cause,
		  pjsip_get_status_text(inv->cause)->ptr));

	PJ_LOG(3,(THIS_FILE, "One call completed, application quitting..."));
	g_complete = 1;

    } else {

	PJ_LOG(3,(THIS_FILE, "Call state changed to %s", 
		  pjsip_inv_state_name(inv->state)));

    }
}


/* This callback is called when dialog has forked. */
static void call_on_forked(pjsip_inv_session *inv, pjsip_event *e)
{
    /* To be done... */
    PJ_UNUSED_ARG(inv);
    PJ_UNUSED_ARG(e);
}


/*
 * Callback when incoming requests outside any transactions and any
 * dialogs are received. We're only interested to hande incoming INVITE
 * request, and we'll reject any other requests with 500 response.
 */
static pj_bool_t on_rx_request( pjsip_rx_data *rdata )
{
    pj_sockaddr hostaddr;
    char temp[80], hostip[PJ_INET6_ADDRSTRLEN];
    pj_str_t local_uri;
    pjsip_dialog *dlg;
    pjmedia_sdp_session *local_sdp;
    pjsip_tx_data *tdata;
    unsigned options = 0;
    pj_status_t status;


    /* 
     * Respond (statelessly) any non-INVITE requests with 500 
     */
    if (rdata->msg_info.msg->line.req.method.id != PJSIP_INVITE_METHOD) {

	if (rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD) {
	    pj_str_t reason = pj_str("Simple UA unable to handle "
				     "this request");

	    pjsip_endpt_respond_stateless( g_endpt, rdata, 
					   500, &reason,
					   NULL, NULL);
	}
	return PJ_TRUE;
    }


    /*
     * Reject INVITE if we already have an INVITE session in progress.
     */
    if (g_inv) {

	pj_str_t reason = pj_str("Another call is in progress");

	pjsip_endpt_respond_stateless( g_endpt, rdata, 
				       500, &reason,
				       NULL, NULL);
	return PJ_TRUE;

    }

    /* Verify that we can handle the request. */
    status = pjsip_inv_verify_request(rdata, &options, NULL, NULL,
				      g_endpt, NULL);
    if (status != PJ_SUCCESS) {

	pj_str_t reason = pj_str("Sorry Simple UA can not handle this INVITE");

	pjsip_endpt_respond_stateless( g_endpt, rdata, 
				       500, &reason,
				       NULL, NULL);
	return PJ_TRUE;
    } 

    /*
     * Generate Contact URI
     */
    if (pj_gethostip(AF, &hostaddr) != PJ_SUCCESS) {
	app_perror(THIS_FILE, "Unable to retrieve local host IP", status);
	return PJ_TRUE;
    }
    pj_sockaddr_print(&hostaddr, hostip, sizeof(hostip), 2);

    pj_ansi_sprintf(temp, "<sip:simpleuas@%s:%d>", 
		    hostip, SIP_PORT);
    local_uri = pj_str(temp);

    /*
     * Create UAS dialog.
     */
    status = pjsip_dlg_create_uas_and_inc_lock( pjsip_ua_instance(),
						rdata,
						&local_uri, /* contact */
						&dlg);
    if (status != PJ_SUCCESS) {
	pjsip_endpt_respond_stateless(g_endpt, rdata, 500, NULL,
				      NULL, NULL);
	return PJ_TRUE;
    }

    /* 
     * Get media capability from media endpoint: 
     */

    status = pjmedia_endpt_create_sdp( g_med_endpt, rdata->tp_info.pool,
				       MAX_MEDIA_CNT, g_sock_info, &local_sdp);
    pj_assert(status == PJ_SUCCESS);
    if (status != PJ_SUCCESS) {
	pjsip_dlg_dec_lock(dlg);
	return PJ_TRUE;
    }


    /* 
     * Create invite session, and pass both the UAS dialog and the SDP
     * capability to the session.
     */
    status = pjsip_inv_create_uas( dlg, rdata, local_sdp, 0, &g_inv);
    pj_assert(status == PJ_SUCCESS);
    if (status != PJ_SUCCESS) {
	pjsip_dlg_dec_lock(dlg);
	return PJ_TRUE;
    }

    /*
     * Invite session has been created, decrement & release dialog lock.
     */
    pjsip_dlg_dec_lock(dlg);


    /*
     * Initially send 180 response.
     *
     * The very first response to an INVITE must be created with
     * pjsip_inv_initial_answer(). Subsequent responses to the same
     * transaction MUST use pjsip_inv_answer().
     */
    status = pjsip_inv_initial_answer(g_inv, rdata, 
				      180, 
				      NULL, NULL, &tdata);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, PJ_TRUE);


    /* Send the 180 response. */  
    status = pjsip_inv_send_msg(g_inv, tdata); 
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, PJ_TRUE);


    /*
     * Now create 200 response.
     */
    status = pjsip_inv_answer( g_inv, 
			       200, NULL,	/* st_code and st_text */
			       NULL,		/* SDP already specified */
			       &tdata);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, PJ_TRUE);

    /*
     * Send the 200 response.
     */
    status = pjsip_inv_send_msg(g_inv, tdata);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, PJ_TRUE);


    /* Done. 
     * When the call is disconnected, it will be reported via the callback.
     */

    return PJ_TRUE;
}

static pj_bool_t on_rx_response( pjsip_rx_data *rdata )
{
	pjsip_dialog *dlg;
	dlg = pjsip_rdata_get_dlg( rdata );
	if (dlg != NULL ) {
		pjsip_transaction *tsx = pjsip_rdata_get_tsx( rdata );
		if ( tsx != NULL && tsx->method.id == PJSIP_INVITE_METHOD) {
			if (tsx->status_code < 200) {
				PJ_LOG(3,("app", "Received provisional response %d", tsx->status_code));
			} else if (tsx->status_code >= 300) {
				PJ_LOG(3,("app", "Dialog failed with status %d", tsx->status_code));
				pjsip_dlg_dec_session(dlg, &mod_simpleua);
				// ACK for non-2xx final response is sent by transaction.
			} else {
				PJ_LOG(3,("app", "Received OK response %d!", tsx->status_code));
				//send_ack( dlg, rdata );
			}
		}
		else if (tsx == NULL && rdata->msg_info.cseq->method.id == PJSIP_INVITE_METHOD
		&& rdata->msg_info.msg->line.status.code/100 == 2)
		{
			// Process 200/OK response retransmission.
			//send_ack( dlg, rdata );
		}
		return PJ_TRUE;
	}
	else {

	}
	// Process other responses not belonging to any dialog
	return PJ_TRUE;
}
 



