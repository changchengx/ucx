/**
 * Copyright (c) 2021, NVIDIA CORPORATION. All rights reserved.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <uct/ib/efa/ib_efa.h>
#include <uct/ib/base/ib_md.h>
#include <ucs/type/status.h>
#include <ucs/debug/log.h>


static uint64_t
uct_ib_efadv_access_flags(const uct_ib_efadv_t *efadv)
{
    uint64_t access_flags = IBV_ACCESS_LOCAL_WRITE;

    if (uct_ib_efadv_has_rdma_read(efadv)) {
        access_flags |= IBV_ACCESS_REMOTE_READ;
    }

    return access_flags;
}

static uct_ib_md_ops_t uct_ib_efa_md_ops;

static ucs_status_t uct_ib_efa_md_open(struct ibv_device *ibv_device,
                                       const uct_ib_md_config_t *md_config,
                                       uct_ib_md_t **p_md)
{
    ucs_status_t status;
    uct_ib_device_t   *dev;
    uct_ib_efadv_md_t *md;

    if (!uct_ib_efadv_check(ibv_device)) {
        return UCS_ERR_UNSUPPORTED;
    }

    md = ucs_calloc(1, sizeof(*md), "ib_efa_md");
    if (md == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    dev = &md->super.dev;

    status = uct_ib_verbs_md_open_common(ibv_device, md_config, &md->super);
    if (status != UCS_OK) {
        ucs_error("uct_ib_verbs_md_open_common() failed for EFA device %s",
                  ibv_get_device_name(ibv_device));
        goto err;
    }

    status = uct_ib_efadv_query(dev->ibv_context, &md->efadv.efadv_attr);
    if (status != UCS_OK) {
        goto err_free_context;
    }

    dev->mr_access_flags = uct_ib_efadv_access_flags(&md->efadv);
    md->super.ops        = &uct_ib_efa_md_ops;

    *p_md = &md->super;
    return UCS_OK;

err_free_context:
    ibv_close_device(dev->ibv_context);
err:
    ucs_free(md);
    return status;
}

static uct_ib_md_ops_t uct_ib_efa_md_ops = {
    .open                = uct_ib_efa_md_open,
    .cleanup             = (uct_ib_md_cleanup_func_t)ucs_empty_function,
    .reg_key             = uct_ib_verbs_reg_key,
    .dereg_key           = uct_ib_verbs_dereg_key,
    .reg_atomic_key      = (uct_ib_md_reg_atomic_key_func_t)ucs_empty_function_return_unsupported,
    .dereg_atomic_key    = (uct_ib_md_dereg_atomic_key_func_t)ucs_empty_function_return_success,
    .reg_multithreaded   = (uct_ib_md_reg_multithreaded_func_t)ucs_empty_function_return_unsupported,
    .dereg_multithreaded = (uct_ib_md_dereg_multithreaded_func_t)ucs_empty_function_return_unsupported,
    .mem_prefetch        = (uct_ib_md_mem_prefetch_func_t)ucs_empty_function_return_success,
    .get_atomic_mr_id    = (uct_ib_md_get_atomic_mr_id_func_t)ucs_empty_function_return_unsupported,
};

UCT_IB_MD_OPS(uct_ib_efa_md_ops, 1);