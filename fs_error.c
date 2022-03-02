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
	int              mgr;
	struct mgr_msg   m;
	struct exlog_err e = EXLOG_ERR_INITIALIZER;
	struct timespec  tp = {1, 0};

	counter_incr(COUNTER_FS_ERROR);
	LK_WRLOCK(&fs_error.lk);
	fs_error.error = 1;
	LK_UNLOCK(&fs_error.lk);

again:
	if ((mgr = mgr_connect(1, &e)) == -1) {
		exlog(LOG_ERR, &e, __func__);
		return;
	}

	m.m = MGR_MSG_SET_FS_ERROR;
	if (mgr_send(mgr, -1, &m, &e) == -1) {
		exlog(LOG_ERR, &e, "%s", __func__);
		close(mgr);
		nanosleep(&tp, NULL);
		goto again;
	}

	if (mgr_recv(mgr, NULL, &m, &e) == -1) {
		exlog(LOG_ERR, &e, "%s", __func__);
		close(mgr);
		nanosleep(&tp, NULL);
		goto again;
	}

	close(mgr);

	if (m.m != MGR_MSG_SET_FS_ERROR_OK)
		exlog(LOG_ERR, NULL, "%s: bad manager response: %d",
		    __func__, m.m);
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
