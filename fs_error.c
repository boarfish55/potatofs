#include "counters.h"
#include "fs_error.h"
#include "mgr.h"
#include "util.h"

struct fs_error {
	uint8_t error;
	rwlk    lk;
} fs_error = { 0, RWLK_INITIALIZER };

void
fs_error_set()
{
	int             mgr;
	struct mgr_msg  m;
	struct xerr     e;
	struct timespec tp = {1, 0};

	xlog(LOG_CRIT, NULL, "%s: incrementing error counter", __func__);
	counter_incr(COUNTER_FS_ERROR);
	LK_WRLOCK(&fs_error.lk);
	fs_error.error = 1;
	LK_UNLOCK(&fs_error.lk);
again:
	if ((mgr = mgr_connect(1, xerrz(&e))) == -1) {
		xlog(LOG_ERR, &e, __func__);
		return;
	}

	m.m = MGR_MSG_SET_FS_ERROR;
	if (mgr_send(mgr, -1, &m, xerrz(&e)) == -1) {
		xlog(LOG_ERR, &e, __func__);
		CLOSE_X(mgr);
		nanosleep(&tp, NULL);
		goto again;
	}

	if (mgr_recv(mgr, NULL, &m, xerrz(&e)) == -1) {
		xlog(LOG_ERR, &e, __func__);
		CLOSE_X(mgr);
		nanosleep(&tp, NULL);
		goto again;
	}

	CLOSE_X(mgr);

	if (m.m == MGR_MSG_SET_FS_ERROR_ERR) {
		xlog(LOG_ERR, &m.v.err, "%s: mgr_recv", __func__);
	} else if (m.m != MGR_MSG_SET_FS_ERROR_OK) {
		xlog(LOG_ERR, NULL, "%s: mgr_recv: unexpected response: %d",
		    __func__, m.m);
	}
}

uint8_t
fs_error_is_set()
{
	uint8_t error;

	LK_RDLOCK(&fs_error.lk);
	error = fs_error.error;
	LK_UNLOCK(&fs_error.lk);
	return error;
}
