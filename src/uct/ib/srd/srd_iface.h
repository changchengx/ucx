/**
 * Copyright (c) 2021, NVIDIA CORPORATION. All rights reserved.
 *
 * See file LICENSE for terms.
 */

#ifndef UCT_SRD_IFACE_H
#define UCT_SRD_IFACE_H

#include "srd_def.h"
#include "srd_ep.h"

#include <uct/base/uct_worker.h>
#include <uct/ib/base/ib_device.h>
#include <uct/ib/base/ib_iface.h>
#include <uct/ib/base/ib_verbs.h>
#include <uct/ib/ud/base/ud_iface_common.h>
#include <ucs/datastruct/sglib_wrapper.h>
#include <ucs/datastruct/ptr_array.h>
#include <ucs/datastruct/sglib.h>
#include <ucs/datastruct/list.h>
#include <ucs/datastruct/arbiter.h>
#include <ucs/async/async.h>
#include <ucs/sys/compiler_def.h>
#include <ucs/sys/sock.h>


BEGIN_C_DECLS


/** @file srd_iface.h */


enum {
    UCT_SRD_IFACE_STAT_RX_DROP,
    UCT_SRD_IFACE_STAT_LAST
};


typedef struct uct_srd_iface_config {
    uct_ib_iface_config_t         super;
    uct_ud_iface_common_config_t  ud_common;
    struct {
        size_t max_get_zcopy;
    } tx;
} uct_srd_iface_config_t;


struct uct_srd_iface {
    uct_ib_iface_t           super;
    struct ibv_qp            *qp;
#ifdef HAVE_DECL_EFA_DV_RDMA_READ
    struct ibv_qp_ex         *qp_ex;
#endif
    struct {
        ucs_mpool_t          mp;
        unsigned             available;
        unsigned             quota;
    } rx;
    struct {
        uct_srd_send_skb_t   *skb; /* ready to use skb */
        ucs_mpool_t          mp;
        int16_t              available;
        ucs_arbiter_t        pending_q;
        struct ibv_sge       sge[UCT_IB_MAX_IOV];
        struct ibv_send_wr   wr_inl;
        struct ibv_send_wr   wr_skb;
    } tx;
    struct {
        unsigned             tx_qp_len;
        unsigned             max_inline;
        size_t               max_send_sge;
        size_t               max_get_zcopy;
    } config;

    UCS_STATS_NODE_DECLARE(stats)

    ucs_conn_match_ctx_t  conn_match_ctx;

    ucs_ptr_array_t          eps;
};


struct uct_srd_ctl_hdr {
    uint8_t                         type;
    uint8_t                         reserved[3];
    union {
        struct {
            uct_srd_ep_addr_t       ep_addr;
            uct_srd_ep_conn_sn_t    conn_sn;
            uint8_t                 path_index;
        } conn_req;
        struct {
            uint32_t                src_ep_id;
        } conn_rep;
        uint32_t                    data;
    };
    uct_srd_peer_name_t             peer;
    /* For CREQ packet, IB address follows */
} UCS_S_PACKED;


extern ucs_config_field_t uct_srd_iface_config_table[];


ucs_status_t uct_srd_iface_query(uct_iface_h tl_iface, uct_iface_attr_t *iface_attr);

void uct_srd_iface_release_desc(uct_recv_desc_t *self, void *desc);

ucs_status_t uct_srd_iface_get_address(uct_iface_h tl_iface, uct_iface_addr_t *addr);

void uct_srd_iface_add_ep(uct_srd_iface_t *iface, uct_srd_ep_t *ep);

void uct_srd_iface_remove_ep(uct_srd_iface_t *iface, uct_srd_ep_t *ep);

void uct_srd_iface_replace_ep(uct_srd_iface_t *iface, uct_srd_ep_t *old_ep, uct_srd_ep_t *new_ep);

ucs_status_t uct_srd_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                 uct_completion_t *comp);

void uct_srd_dump_packet(uct_base_iface_t *iface, uct_am_trace_type_t type,
                         void *data, size_t length, size_t valid_length,
                         char *buffer, size_t max);

uct_srd_send_skb_t *uct_srd_iface_ctl_skb_get(uct_srd_iface_t *iface);

/* management of connecting endpoints (cep) is similar to UD */
void uct_srd_iface_cep_cleanup(uct_srd_iface_t *iface);

uct_srd_ep_conn_sn_t
uct_srd_iface_cep_get_conn_sn(uct_srd_iface_t *iface,
                              const uct_ib_address_t *ib_addr,
                              const uct_srd_iface_addr_t *if_addr,
                              int path_index);

void uct_srd_iface_cep_insert_ep(uct_srd_iface_t *iface,
                                 const uct_ib_address_t *ib_addr,
                                 const uct_srd_iface_addr_t *if_addr,
                                 int path_index, uct_srd_ep_conn_sn_t conn_sn,
                                 uct_srd_ep_t *ep);

uct_srd_ep_t *uct_srd_iface_cep_get_ep(uct_srd_iface_t *iface,
                                       const uct_ib_address_t *ib_addr,
                                       const uct_srd_iface_addr_t *if_addr,
                                       int path_index,
                                       uct_srd_ep_conn_sn_t conn_sn,
                                       int is_private);

void uct_srd_iface_cep_remove_ep(uct_srd_iface_t *iface, uct_srd_ep_t *ep);

unsigned uct_srd_iface_dispatch_pending_rx_do(uct_srd_iface_t *iface);

ucs_status_t
uct_srd_iface_unpack_peer_address(uct_srd_iface_t *iface,
                                  const uct_ib_address_t *ib_addr,
                                  const uct_srd_iface_addr_t *if_addr,
                                  int path_index, void *address_p);

static UCS_F_ALWAYS_INLINE int uct_srd_iface_can_tx(uct_srd_iface_t *iface)
{
    return iface->tx.available > 0;
}

static UCS_F_ALWAYS_INLINE int uct_srd_iface_has_skbs(uct_srd_iface_t *iface)
{
    return iface->tx.skb || !ucs_mpool_is_empty(&iface->tx.mp);
}

static inline uct_ib_address_t* uct_srd_creq_ib_addr(uct_srd_ctl_hdr_t *conn_req)
{
    ucs_assert(conn_req->type == UCT_SRD_PACKET_CREQ);
    return (uct_ib_address_t*)(conn_req + 1);
}

static UCS_F_ALWAYS_INLINE void uct_srd_enter(uct_srd_iface_t *iface)
{
    UCS_ASYNC_BLOCK(iface->super.super.worker->async);
}

static UCS_F_ALWAYS_INLINE void uct_srd_leave(uct_srd_iface_t *iface)
{
    UCS_ASYNC_UNBLOCK(iface->super.super.worker->async);
}

static UCS_F_ALWAYS_INLINE void
uct_srd_iface_progress_pending(uct_srd_iface_t *iface)
{
    if (!uct_srd_iface_can_tx(iface)) {
        return;
    }

    ucs_arbiter_dispatch(&iface->tx.pending_q, 1, uct_srd_ep_do_pending, NULL);
}


/* TODO: shouldn't we compare the length with seg_size instead of MTU? */
#if ENABLE_PARAMS_CHECK
#define UCT_SRD_CHECK_LENGTH(iface, header_len, payload_len, msg) \
     do { \
         int mtu; \
         mtu =  uct_ib_mtu_value(uct_ib_iface_port_attr(&(iface)->super)->active_mtu); \
         UCT_CHECK_LENGTH(sizeof(uct_srd_neth_t) + payload_len + header_len, \
                          0, mtu, msg); \
     } while(0);

#define UCT_SRD_CHECK_AM_BCOPY_LENGTH(iface, len) \
    UCT_SRD_CHECK_LENGTH(iface, 0, len, "am_bcopy")

#define UCT_SRD_CHECK_AM_ZCOPY_LENGTH(iface, header_len, payload_len) \
    UCT_SRD_CHECK_LENGTH(iface, header_len, payload_len, "am_zcopy payload")

#else
#define UCT_SRD_CHECK_AM_BCOPY_LENGTH(iface, len)
#define UCT_SRD_CHECK_AM_ZCOPY_LENGTH(iface, header_len, payload_len)
#endif

END_C_DECLS

#endif
