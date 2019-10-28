/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <sys/types.h>

#include <sys/ioctl.h>
#include <dev/usb/usb.h>
#include <dev/usb/usbhid.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <usbhid.h>

#include "fido.h"

#define MAX_REPORT_LEN	(sizeof(((struct usb_ctl_report *)(NULL))->ucr_data))

struct hid_openbsd {
	int fd;
	size_t report_in_len;
	size_t report_out_len;
};

int
fido_dev_info_manifest(fido_dev_info_t *devlist, size_t ilen, size_t *olen)
{
	(void)devlist; /* XXX */
	(void)ilen; /* XXX */
	(void)olen; /* XXX */

	return FIDO_ERR_INTERNAL; /* XXX unimplemented */
}

void *
hid_open(const char *path)
{
	struct hid_openbsd *ret = NULL;
	report_desc_t rdesc = NULL;
	int len, usb_report_id = 0;

	if ((ret = calloc(1, sizeof(*ret))) == NULL ||
	    (ret->fd = open(path, O_RDWR)) < 0) {
		free(ret);
		return (NULL);
	}
	if (ioctl(ret->fd, USB_GET_REPORT_ID, &usb_report_id) != 0) {
		log_debug("%s: failed to get report ID: %s", __func__,
		    strerror(errno));
		goto fail;
	}
	if ((rdesc = hid_get_report_desc(ret->fd)) == 0) {
		log_debug("%s: failed to get report descriptor", __func__);
		goto fail;
	}
	if ((len = hid_report_size(rdesc, hid_input, usb_report_id)) <= 0 ||
	    (size_t)len > MAX_REPORT_LEN) {
		log_debug("%s: bad input report size %d", __func__, len);
		goto fail;
	}
	ret->report_in_len = (size_t)len;
	if ((len = hid_report_size(rdesc, hid_input, usb_report_id)) <= 0 ||
	    (size_t)len > MAX_REPORT_LEN) {
		log_debug("%s: bad output report size %d", __func__, len);
 fail:
		hid_dispose_report_desc(rdesc);
		close(ret->fd);
		free(ret);
		return NULL;
	}	
	ret->report_out_len = (size_t)len;
	log_debug("%s: USB report ID %d, inlen = %zu outlen = %zu", __func__,
	    usb_report_id, ret->report_in_len, ret->report_out_len);
	return (ret);
}

void
hid_close(void *handle)
{
	struct hid_openbsd *ctx = (struct hid_openbsd *)handle;

	close(ctx->fd);
	free(ctx);
}

int
hid_read(void *handle, unsigned char *buf, size_t len, int ms)
{
	struct hid_openbsd *ctx = (struct hid_openbsd *)handle;
	ssize_t r;

	(void)ms; /* XXX */

	if (len != ctx->report_in_len) {
		log_debug("%s: invalid len: got %zu, want %zu", __func__,
		    len, ctx->report_in_len);
		return (-1);
	}
	if ((r = read(ctx->fd, buf, len)) == -1 || (size_t)r != len) {
		log_debug("%s: read: %s", __func__, strerror(errno));
		return (-1);
	}
	return ((int)len);
}

int
hid_write(void *handle, const unsigned char *buf, size_t len)
{
	struct hid_openbsd *ctx = (struct hid_openbsd *)handle;
	struct usb_ctl_report report;

	if (len != ctx->report_out_len + 1) {
		log_debug("%s: invalid len: got %zu, want %zu", __func__,
		    len, ctx->report_out_len);
		return (-1);
	}

	memset(&report, 0, sizeof(report));
	report.ucr_report = buf[0];
	memcpy(report.ucr_data, buf + 1, len - 1);
	if (ioctl(ctx->fd, USB_SET_REPORT, &report) != 0) {
		log_debug("%s: set report: %s", __func__, strerror(errno));
		return (-1);
	}

	return ((int)len);
}
