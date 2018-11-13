// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include "glob.h"
#include "nterr.h"
#include "smb2pdu.h"
#include "smb_common.h"
#include "mgmt/user_session.h"

static int check_smb2_hdr(struct smb2_hdr *hdr)
{
	/*
	 * Make sure that this really is an SMB, that it is a response.
	 */
	if (hdr->Flags & SMB2_FLAGS_SERVER_TO_REDIR)
		return 1;
	return 0;
}

/*
 *  The following table defines the expected "StructureSize" of SMB2 responses
 *  in order by SMB2 command.  This is similar to "wct" in SMB/CIFS responses.
 *
 *  Note that commands are defined in smb2pdu.h in le16 but the array below is
 *  indexed by command in host byte order
 */
static const __le16 smb2_req_struct_sizes[NUMBER_OF_SMB2_COMMANDS] = {
	/* SMB2_NEGOTIATE */ cpu_to_le16(36),
	/* SMB2_SESSION_SETUP */ cpu_to_le16(25),
	/* SMB2_LOGOFF */ cpu_to_le16(4),
	/* SMB2_TREE_CONNECT */ cpu_to_le16(9),
	/* SMB2_TREE_DISCONNECT */ cpu_to_le16(4),
	/* SMB2_CREATE */ cpu_to_le16(57),
	/* SMB2_CLOSE */ cpu_to_le16(24),
	/* SMB2_FLUSH */ cpu_to_le16(24),
	/* SMB2_READ */ cpu_to_le16(49),
	/* SMB2_WRITE */ cpu_to_le16(49),
	/* SMB2_LOCK */ cpu_to_le16(48),
	/* SMB2_IOCTL */ cpu_to_le16(57),
	/* SMB2_CANCEL */ cpu_to_le16(4),
	/* SMB2_ECHO */ cpu_to_le16(4),
	/* SMB2_QUERY_DIRECTORY */ cpu_to_le16(33),
	/* SMB2_CHANGE_NOTIFY */ cpu_to_le16(32),
	/* SMB2_QUERY_INFO */ cpu_to_le16(41),
	/* SMB2_SET_INFO */ cpu_to_le16(33),
	/* use 44 for lease break */
	/* SMB2_OPLOCK_BREAK */ cpu_to_le16(36)
};

/*
 * The size of the variable area depends on the offset and length fields
 * located in different fields for various SMB2 responses. SMB2 responses
 * with no variable length info, show an offset of zero for the offset field.
 */
static const bool has_smb2_data_area[NUMBER_OF_SMB2_COMMANDS] = {
	/* SMB2_NEGOTIATE */ true,
	/* SMB2_SESSION_SETUP */ true,
	/* SMB2_LOGOFF */ false,
	/* SMB2_TREE_CONNECT */	true,
	/* SMB2_TREE_DISCONNECT */ false,
	/* SMB2_CREATE */ true,
	/* SMB2_CLOSE */ false,
	/* SMB2_FLUSH */ false,
	/* SMB2_READ */	true,
	/* SMB2_WRITE */ true,
	/* SMB2_LOCK */	true,
	/* SMB2_IOCTL */ true,
	/* SMB2_CANCEL */ false, /* BB CHECK this not listed in documentation */
	/* SMB2_ECHO */ false,
	/* SMB2_QUERY_DIRECTORY */ true,
	/* SMB2_CHANGE_NOTIFY */ false,
	/* SMB2_QUERY_INFO */ true,
	/* SMB2_SET_INFO */ true,
	/* SMB2_OPLOCK_BREAK */ false
};

static int get_neg_context_size(char *buf, int *off, int *len)
{
	int i = 0;
	struct smb2_negotiate_req *req = (struct smb2_negotiate_req *)buf;
	char *pneg_ctxt;
	__le16 *ContextType;
	int neg_ctxt_cnt = le16_to_cpu(req->NegotiateContextCount);

	*off = le32_to_cpu(req->NegotiateContextOffset);
	if (*off == 0 || neg_ctxt_cnt == 0)
		return 0;

	pneg_ctxt = buf + le32_to_cpu(req->NegotiateContextOffset) + 4;
	ContextType = (__le16 *)pneg_ctxt;
	while (i++ < neg_ctxt_cnt) {
		if (*ContextType == SMB2_PREAUTH_INTEGRITY_CAPABILITIES) {
			pneg_ctxt +=
				sizeof(struct smb2_preauth_neg_context) + 2;
			*len += sizeof(struct smb2_preauth_neg_context) + 2;
			ContextType = (__le16 *)pneg_ctxt;
		} else if (*ContextType == SMB2_ENCRYPTION_CAPABILITIES) {
			pneg_ctxt +=
				sizeof(struct smb2_encryption_neg_context) + 2;
			*len += sizeof(struct smb2_encryption_neg_context) + 2;
			ContextType = (__le16 *)pneg_ctxt;
		}
	}
	*len -= 2;

	if (*len <= 0)
		return 0;
	return 1;
}

/*
 * Returns the pointer to the beginning of the data area. Length of the data
 * area and the offset to it (from the beginning of the smb are also returned.
 */
char *smb2_get_data_area_len(int *off, int *len, struct smb2_hdr *hdr)
{
	*off = 0;
	*len = 0;

	/* error responses do not have data area */
	if (hdr->Status && hdr->Status != NT_STATUS_MORE_PROCESSING_REQUIRED &&
			(((struct smb2_err_rsp *)hdr)->StructureSize) ==
			SMB2_ERROR_STRUCTURE_SIZE2)
		return NULL;

	/*
	 * Following commands have data areas so we have to get the location
	 * of the data buffer offset and data buffer length for the particular
	 * command.
	 */
	switch (hdr->Command) {
	case SMB2_NEGOTIATE:
		if (!get_neg_context_size((char *)hdr, off, len)) {
			*off = SMB2_HEADER_STRUCTURE_SIZE + 36;
			*len = le16_to_cpu(((struct smb2_negotiate_req *)
				hdr)->DialectCount) * 2;
		}
		break;
	case SMB2_SESSION_SETUP:
		*off = le16_to_cpu(
		     ((struct smb2_sess_setup_req *)hdr)->SecurityBufferOffset);
		*len = le16_to_cpu(
		     ((struct smb2_sess_setup_req *)hdr)->SecurityBufferLength);
		break;
	case SMB2_TREE_CONNECT:
		*off = le16_to_cpu(
		     ((struct smb2_tree_connect_req *)hdr)->PathOffset);
		*len = le16_to_cpu(
		     ((struct smb2_tree_connect_req *)hdr)->PathLength);
		break;
	case SMB2_CREATE:
	{
		if (((struct smb2_create_req *)hdr)->CreateContextsLength) {
			*off = le32_to_cpu(((struct smb2_create_req *)
				hdr)->CreateContextsOffset);
			*len = le32_to_cpu(((struct smb2_create_req *)
				hdr)->CreateContextsLength);
			break;
		}

		*off = le16_to_cpu(
		     ((struct smb2_create_req *)hdr)->NameOffset);
		*len = le16_to_cpu(
		     ((struct smb2_create_req *)hdr)->NameLength);
		break;
	}
	case SMB2_QUERY_INFO:
		*off = le16_to_cpu(
		     ((struct smb2_query_info_req *)hdr)->InputBufferOffset);
		*len = le32_to_cpu(
		     ((struct smb2_query_info_req *)hdr)->InputBufferLength);
		break;
	case SMB2_SET_INFO:
		*off = le16_to_cpu(
		     ((struct smb2_set_info_req *)hdr)->BufferOffset);
		*len = le32_to_cpu(
		     ((struct smb2_set_info_req *)hdr)->BufferLength);
		break;
	case SMB2_READ:
		*off = le16_to_cpu(
		     ((struct smb2_read_req *)hdr)->ReadChannelInfoOffset);
		*len = le16_to_cpu(
		     ((struct smb2_read_req *)hdr)->ReadChannelInfoLength);
		break;
	case SMB2_WRITE:
		if (((struct smb2_write_req *)hdr)->DataOffset) {
			*off = le16_to_cpu(
			     ((struct smb2_write_req *)hdr)->DataOffset);
			*len = le32_to_cpu(
				((struct smb2_write_req *)hdr)->Length);
			break;
		}

		*off = le16_to_cpu(
		     ((struct smb2_write_req *)hdr)->WriteChannelInfoOffset);
		*len = le16_to_cpu(
		     ((struct smb2_write_req *)hdr)->WriteChannelInfoLength);
		break;
	case SMB2_QUERY_DIRECTORY:
		*off = le16_to_cpu(
		     ((struct smb2_query_directory_req *)hdr)->FileNameOffset);
		*len = le16_to_cpu(
		     ((struct smb2_query_directory_req *)hdr)->FileNameLength);
		break;
	case SMB2_LOCK:
	{
		int lock_count;

		/*
		 * smb2_lock request size is 48 included single
		 * smb2_lock_element structure size.
		 */
		lock_count = le16_to_cpu(
			((struct smb2_lock_req *)hdr)->LockCount) - 1;
		if (lock_count > 0) {
			*off = SMB2_HEADER_STRUCTURE_SIZE + 48;
			*len = sizeof(struct smb2_lock_element) * lock_count;
		}
		break;
	}
	case SMB2_IOCTL:
		*off = le32_to_cpu(
		     ((struct smb2_ioctl_req *)hdr)->InputOffset);
		*len = le32_to_cpu(((struct smb2_ioctl_req *)hdr)->InputCount);
		break;
	default:
		cifsd_debug("no length check for command\n");
		break;
	}

	/*
	 * Invalid length or offset probably means data area is invalid, but
	 * we have little choice but to ignore the data area in this case.
	 */
	if (*off > 4096) {
		cifsd_debug("offset %d too large, data area ignored\n", *off);
		*len = 0;
		*off = 0;
	} else if (*off < 0) {
		cifsd_debug("negative offset %d to data invalid ignore data area\n",
			*off);
		*off = 0;
		*len = 0;
	} else if (*len < 0) {
		cifsd_debug("negative data length %d invalid, data area ignored\n",
			*len);
		*len = 0;
	} else if (*len > 128 * 1024) {
		cifsd_debug("data area larger than 128K: %d\n", *len);
		*len = 0;
	}

	/* return pointer to beginning of data area, ie offset from SMB start */
	if ((*off != 0) && (*len != 0))
		return (char *)hdr + *off;
	else
		return NULL;
}

/*
 * Calculate the size of the SMB message based on the fixed header
 * portion, the number of word parameters and the data portion of the message.
 */
unsigned int smb2_calc_size(void *buf)
{
	struct smb2_pdu *pdu = (struct smb2_pdu *)buf;
	struct smb2_hdr *hdr = &pdu->hdr;
	int offset; /* the offset from the beginning of SMB to data area */
	int data_length; /* the length of the variable length data area */
	/* Structure Size has already been checked to make sure it is 64 */
	int len = le16_to_cpu(hdr->StructureSize);

	/*
	 * StructureSize2, ie length of fixed parameter area has already
	 * been checked to make sure it is the correct length.
	 */
	len += le16_to_cpu(pdu->StructureSize2);

	if (has_smb2_data_area[le16_to_cpu(hdr->Command)] == false)
		goto calc_size_exit;

	smb2_get_data_area_len(&offset, &data_length, hdr);
	cifsd_debug("SMB2 data length %d offset %d\n", data_length, offset);

	if (data_length > 0) {
		/*
		 * Check to make sure that data area begins after fixed area,
		 * Note that last byte of the fixed area is part of data area
		 * for some commands, typically those with odd StructureSize,
		 * so we must add one to the calculation.
		 */
		if (offset + 1 < len)
			cifsd_debug("data area offset %d overlaps SMB2 header %d\n",
					offset + 1, len);
		else
			len = offset + data_length;
	}
calc_size_exit:
	cifsd_debug("SMB2 len %d\n", len);
	return len;
}

int smb2_check_message(struct cifsd_work *work)
{
	char *buf = REQUEST_BUF(work);
	struct smb2_pdu *pdu = (struct smb2_pdu *)buf;
	struct smb2_hdr *hdr = &pdu->hdr;
	int command;
	__u32 clc_len;  /* calculated length */
	__u32 len = get_rfc1002_length(buf);

	if (work->next_smb2_rcv_hdr_off) {
		pdu = (struct smb2_pdu *)(buf + work->next_smb2_rcv_hdr_off);
		hdr = &pdu->hdr;
	}

	if (le32_to_cpu(hdr->NextCommand) > 0)
		len = le32_to_cpu(hdr->NextCommand);
	else if (work->next_smb2_rcv_hdr_off) {
		len -= work->next_smb2_rcv_hdr_off;
		len = round_up(len, 8);
	}

	if (check_smb2_hdr(hdr))
		return 1;

	if (hdr->StructureSize != SMB2_HEADER_STRUCTURE_SIZE) {
		cifsd_err("Illegal structure size %u\n",
			le16_to_cpu(hdr->StructureSize));
		return 1;
	}

	command = le16_to_cpu(hdr->Command);
	if (command >= NUMBER_OF_SMB2_COMMANDS) {
		cifsd_err("Illegal SMB2 command %d\n", command);
		return 1;
	}

	if (smb2_req_struct_sizes[command] != pdu->StructureSize2) {
		if (command != SMB2_OPLOCK_BREAK_HE && (hdr->Status == 0 ||
			pdu->StructureSize2 != SMB2_ERROR_STRUCTURE_SIZE2)) {
			/* error packets have 9 byte structure size */
			cifsd_err("Illegal response size %u for command %d\n",
				le16_to_cpu(pdu->StructureSize2), command);
			return 1;
		} else if (command == SMB2_OPLOCK_BREAK_HE
				&& (hdr->Status == 0)
				&& (le16_to_cpu(pdu->StructureSize2) != 44)
				&& (le16_to_cpu(pdu->StructureSize2) != 36)) {
			/* special case for SMB2.1 lease break message */
			cifsd_err("Illegal response size %d for oplock break\n",
				le16_to_cpu(pdu->StructureSize2));
			return 1;
		}
	}

	clc_len = smb2_calc_size(hdr);
	if (len != clc_len) {
		__u64 mid = le64_to_cpu(hdr->MessageId);
		/* server can return one byte more due to implied bcc[0] */
		if (clc_len == len + 1)
			return 0;

		/*
		 * Some windows servers (win2016) will pad also the final
		 * PDU in a compound to 8 bytes.
		 */
		if (((clc_len + 7) & ~7) == len)
			return 0;

		/*
		 * windows client also pad up to 8 bytes when compounding.
		 * If pad is longer than eight bytes, log the server behavior
		 * (once), since may indicate a problem but allow it and
		 * continue since the frame is parseable.
		 */
		if (clc_len < len) {
			cifsd_debug(
				"srv rsp padded more than expected. Length %d not %d for cmd:%d mid:%llu\n",
					len, clc_len, command, mid);
			return 0;
		}
		cifsd_err(
			"srv rsp too short, len %d not %d. cmd:%d mid:%llu\n",
				len, clc_len, command, mid);

		return 1;
	}
	return 0;
}

int smb2_negotiate_request(struct cifsd_work *work)
{
	return cifsd_smb_negotiate_common(work, SMB2_NEGOTIATE_HE);
}