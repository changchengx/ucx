#! /bin/bash

export UCX_MAX_EAGER_LANES=2
export UCX_TLS=rc_x
export UCX_IB_SEG_SIZE=2k
export UCX_RC_RX_QUEUE_LEN=1024
export UCX_RC_MAX_RD_ATOMIC=16
export UCX_RC_ROCE_PATH_FACTOR=2
export UCX_RNDV_THRESH=32k
export UCX_IB_TRAFFIC_CLASS=160
export UCX_SOCKADDR_CM_ENABLE=y
export UCX_RC_MAX_GET_ZCOPY=32k
export UCX_RC_TX_NUM_GET_BYTES=32k
export UCX_RC_TX_CQ_MODERATION=0

stdbuf -o0 ./install/bin/io_demo -d 65536 2>&1 | tee srv.log
