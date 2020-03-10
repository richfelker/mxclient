#include <bearssl.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <semaphore.h>
#include <stdio.h>

struct start_ctx {
	int p, s;
	const char *hostname;
	const unsigned char *tlsa;
	size_t tlsa_len;
	sem_t sem;
	int err;
	FILE *errf;
};

struct vt_wrap {
	br_x509_class vt;
	unsigned (*old_end_chain)(const br_x509_class **ctx);
	const unsigned char *tlsa;
	size_t tlsa_len;
};

int check_tlsa(const br_x509_pkey *, const unsigned char *, size_t);

static unsigned dummy(const br_x509_class **ctx)
{
	//br_x509_minimal_context *xc = (br_x509_minimal_context *)ctx;
	struct vt_wrap *vtw = (struct vt_wrap *)(*ctx);
	unsigned r = vtw->old_end_chain(ctx);
	if (r && r != BR_ERR_X509_NOT_TRUSTED) return r;
	const br_x509_pkey *pkey = (*ctx)->get_pkey(ctx, 0);
	if (vtw->tlsa_len && check_tlsa(pkey, vtw->tlsa, vtw->tlsa_len)<0)
		return BR_ERR_X509_NOT_TRUSTED;
	return 0;
}

static void *tlsthread(void *vc)
{
	struct start_ctx *ctx = vc;
	int s = ctx->s, p = ctx->p;

	br_ssl_client_context sc;
	br_x509_minimal_context xc;
	br_ssl_client_init_full(&sc, &xc, 0, 0);

	unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
	br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);

	br_ssl_client_reset(&sc, ctx->hostname, 0);
	struct vt_wrap vtw = { .vt = *xc.vtable };
	vtw.old_end_chain = vtw.vt.end_chain;
	vtw.vt.end_chain = dummy;
	vtw.tlsa = ctx->tlsa;
	vtw.tlsa_len = ctx->tlsa_len;
	xc.vtable = &vtw.vt;

	struct timeval no_to = { 0 };
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &no_to, sizeof no_to);
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &no_to, sizeof no_to);
	fcntl(p, F_SETFL, fcntl(p, F_GETFL) | O_NONBLOCK);

	int started = 0;

	for (;;) {
		unsigned st = br_ssl_engine_current_state(&sc.eng);
		struct pollfd pfd[2] = { { .fd = p }, { .fd = s } };
		if (!started) {
			if (st == BR_SSL_CLOSED) {
				if (ctx->errf)
					fprintf(ctx->errf, "BearSSL error %d\n",
						br_ssl_engine_last_error(&sc.eng));
				ctx->err = 1;
				sem_post(&ctx->sem);
				return 0;
			}
			if (st & BR_SSL_SENDAPP) {
				ctx->err = 0;
				sem_post(&ctx->sem);
				started = 1;
			}
		}
		if (st == BR_SSL_CLOSED) {
			//int err = br_ssl_engine_last_error(&sc.eng);
			break;
		}
		if (st & BR_SSL_SENDREC)
			pfd[1].events |= POLLOUT;
		if (st & BR_SSL_RECVREC)
			pfd[1].events |= POLLIN;
		if (st & BR_SSL_SENDAPP)
			pfd[0].events |= POLLIN;
		if (st & BR_SSL_RECVAPP)
			pfd[0].events |= POLLOUT;
		if (poll(pfd, 2, -1) < 1) continue;
		if (pfd[0].revents & POLLIN) {
			size_t len;
			unsigned char *buf = br_ssl_engine_sendapp_buf(&sc.eng, &len);
			len = read(p, buf, len);
			if (!len || len==-1) break;
			br_ssl_engine_sendapp_ack(&sc.eng, len);
			br_ssl_engine_flush(&sc.eng, 0);
			continue;
		}
		if (pfd[0].revents & POLLOUT) {
			size_t len;
			unsigned char *buf = br_ssl_engine_recvapp_buf(&sc.eng, &len);
			len = write(p, buf, len);
			if (!len || len==-1) break;
			br_ssl_engine_recvapp_ack(&sc.eng, len);
			continue;
		}
		if (pfd[1].revents & POLLOUT) {
			size_t len;
			unsigned char *buf = br_ssl_engine_sendrec_buf(&sc.eng, &len);
			len = write(s, buf, len);
			if (!len || len==-1) break;
			br_ssl_engine_sendrec_ack(&sc.eng, len);
			continue;
		}
		if (pfd[1].revents & POLLIN) {
			size_t len;
			unsigned char *buf = br_ssl_engine_recvrec_buf(&sc.eng, &len);
			len = read(s, buf, len);
			if (!len || len==-1) break;
			br_ssl_engine_recvrec_ack(&sc.eng, len);
			continue;
		}
	}
	close(s);
	close(p);
	return 0;
}

int starttls_client(int s, const char *hostname, const unsigned char *tlsa, size_t tlsa_len, FILE *errf)
{
	s = fcntl(s, F_DUPFD_CLOEXEC, 0);
	if (s < 0) return -1;

	struct timeval sto = { 0 }, rto = { 0 };
	getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &rto, &(socklen_t){ sizeof rto });
	getsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &sto, &(socklen_t){ sizeof sto });

	int sp[2];
	if (!socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, sp)) {
		setsockopt(sp[0], SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof rto);
		setsockopt(sp[0], SOL_SOCKET, SO_SNDTIMEO, &sto, sizeof sto);

		struct start_ctx ctx;
		sem_init(&ctx.sem, 0, 0);
		ctx.s = s;
		ctx.p = sp[1];
		ctx.hostname = hostname;
		ctx.tlsa = tlsa;
		ctx.tlsa_len = tlsa_len;
		ctx.errf = errf;
		pthread_t td;
		if (!pthread_create(&td, 0, tlsthread, &ctx)) {
			sem_wait(&ctx.sem);
			if (!ctx.err) {
				pthread_detach(td);
				return sp[0];
			}
			pthread_join(td, 0);
		}
		close(sp[0]);
		close(sp[1]);
	}
	close(s);
	return -1;
		
}
