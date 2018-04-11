/* packet-pdcp-nr.h
 *
 * Martin Mathieson
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "packet-rohc.h"

/* Direction */
#define DIRECTION_UPLINK   0
#define DIRECTION_DOWNLINK 1

enum pdcp_nr_plane
{
    NR_SIGNALING_PLANE = 1,
    NR_USER_PLANE = 2
};

typedef enum NRBearerType
{
    Bearer_DCCH=1,
    Bearer_BCCH_BCH=2,
    Bearer_BCCH_DL_SCH=3,
    Bearer_CCCH=4,
    Bearer_PCCH=5,
} NRBearerType;


#define PDCP_NR_SN_LENGTH_12_BITS 12
#define PDCP_NR_SN_LENGTH_18_BITS 18



/* Info attached to each nr PDCP/RoHC packet */
typedef struct pdcp_nr_info
{
    /* Bearer info is needed for RRC parsing */
    guint8             direction;
    guint16            ueid;
    NRBearerType       bearerType;
    guint8             bearerId;

    /* Details of PDCP header */
    enum pdcp_nr_plane    plane;
    guint8             seqnum_length;

    /* RoHC settings */
    rohc_info          rohc;

    guint8             is_retx;
} pdcp_nr_info;



/*****************************************************************/
/* UDP framing format                                            */
/* -----------------------                                       */
/* Several people have asked about dissecting PDCP by framing    */
/* PDUs over IP.  A suggested format over UDP has been defined   */
/* and implemented by this dissector, using the definitions      */
/* below. A link to an example program showing you how to encode */
/* these headers and send nr PDCP PDUs on a UDP socket is        */
/* provided at https://wiki.wireshark.org/PDCP-nr                */
/*                                                               */
/* A heuristic dissecter (enabled by a preference) will          */
/* recognise a signature at the beginning of these frames.       */
/* Until someone is using this format, suggestions for changes   */
/* are welcome.                                                  */
/*****************************************************************/


/* Signature.  Rather than try to define a port for this, or make the
   port number a preference, frames will start with this string (with no
   terminating NULL */
#define PDCP_NR_START_STRING "pdcp-nr"


/* The format for fields is to have the tag, followed by the value
  (there is no length field, it's implicit from the tag).
  The allowed values for each field should be taken from pdcp_nr_info above. */

#define PDCP_NR_PLANE_TAG                  0x02
/* 1 byte, mandatory */

#define PDCP_NR_SEQNUM_LENGTH_TAG          0x03
/* 1 byte, mandatory */

#define PDCP_NR_DIRECTION_TAG              0x04
/* 1 byte, mandatory */

#define PDCP_NR_BEARER_TYPE_TAG            0x05
/* 1 byte, mandatory */

#define PDCP_NR_BEARER_ID_TAG              0x06
/* 1 byte, mandatory depending upon bearer type */

#define PDCP_NR_UEID_TAG                   0x07
/* 2 bytes, network order.  Optional, but needed if > 1 UE logged. */


#define PDCP_NR_ROHC_COMPRESSION_TAG       0x08
/* 1 byte, network order (mandatory for user-plane) */

/* N.B. The following ROHC values only have significance if rohc_compression
   is in use for the current channel */

#define PDCP_NR_ROHC_IP_VERSION_TAG        0x09
/* 2 bytes, network order */

#define PDCP_NR_ROHC_CID_INC_INFO_TAG      0x0A
/* 1 byte */

#define PDCP_NR_ROHC_LARGE_CID_PRES_TAG    0x0B
/* 1 byte */

#define PDCP_NR_ROHC_MODE_TAG              0x0C
/* 1 byte */

#define PDCP_NR_ROHC_RND_TAG               0x0D
/* 1 byte */

#define PDCP_NR_ROHC_UDP_CHECKSUM_PRES_TAG 0x0E
/* 1 byte */

#define PDCP_NR_ROHC_PROFILE_TAG           0x0F
/* 2 bytes, network order */


/* PDCP PDU. Following this tag comes the actual PDCP PDU (there is no length, the PDU
   continues until the end of the frame) */
#define PDCP_NR_PAYLOAD_TAG                0x01


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
