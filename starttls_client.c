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
#include <arpa/nameser.h>

void pkey_hash(unsigned char *, unsigned char *, const br_x509_pkey *);
int check_tlsa(const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, int, const unsigned char *, size_t);

struct start_ctx {
	int p, s;
	const char *hostname;
	const unsigned char *tlsa;
	size_t tlsa_len;
	sem_t sem;
	int err;
	FILE *errf;
};

struct x509_dane_context {
	const br_x509_class *vtable;
	br_x509_minimal_context minimal;
	const unsigned char *tlsa;
	size_t tlsa_len;
	int trusted;
	int chain_idx;
	br_x509_decoder_context dec;
	br_sha256_context sha256;
	br_sha512_context sha512;
	const br_x509_pkey *ee_pkey;
	FILE *errf;
};

static void start_chain(const br_x509_class **ctx, const char *server_name)
{
	struct x509_dane_context *c = (void *)ctx;
	c->minimal.vtable->start_chain(&c->minimal.vtable, server_name);
}

static void start_cert(const br_x509_class **ctx, uint32_t length)
{
	struct x509_dane_context *c = (void *)ctx;
	if (c->trusted) return;
	c->minimal.vtable->start_cert(&c->minimal.vtable, length);
	br_x509_decoder_init(&c->dec, 0, 0);
	br_sha256_init(&c->sha256);
	br_sha512_init(&c->sha512);
}

static void append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
	struct x509_dane_context *c = (void *)ctx;
	if (c->trusted) return;
	c->minimal.vtable->append(&c->minimal.vtable, buf, len);
	br_x509_decoder_push(&c->dec, buf, len);
	br_sha256_update(&c->sha256, buf, len);
	br_sha512_update(&c->sha512, buf, len);
}

static void print_tlsa(FILE *f, const unsigned char *tlsa, size_t tlsa_len, int idx)
{
	ns_msg msg;
	if (ns_initparse(tlsa, tlsa_len, &msg) < 0) return;
	ns_rr rr;
	if (!ns_parserr(&msg, ns_s_an, idx, &rr)) {
		const unsigned char *data = ns_rr_rdata(rr);
		size_t len = ns_rr_rdlen(rr);
		fprintf(f, "%d %d %d ", data[0], data[1], data[2]);
		for (int i=3; i<len; i++)
			fprintf(f, "%.2X", data[i]);
		fprintf(f, "\n");
	}
}

static void end_cert(const br_x509_class **ctx)
{
	struct x509_dane_context *c = (void *)ctx;
	if (c->trusted) return;
	c->minimal.vtable->end_cert(&c->minimal.vtable);

	const br_x509_pkey *pkey = br_x509_decoder_get_pkey(&c->dec);
	unsigned char pkey_sha256[32], pkey_sha512[64];
	pkey_hash(pkey_sha256, pkey_sha512, pkey);

	unsigned char cert_sha256[32], cert_sha512[64];
	br_sha256_out(&c->sha256, cert_sha256);
	br_sha512_out(&c->sha512, cert_sha512);

	int r = check_tlsa(pkey_sha256, pkey_sha512, cert_sha256, cert_sha512, !c->chain_idx, c->tlsa, c->tlsa_len);
	if (r>=0) {
		c->trusted = 1;
		if (!c->chain_idx) c->ee_pkey = pkey;
		if (c->errf) {
			if (!c->tlsa_len) {
				fprintf(c->errf, "No trust anchor; accepted key ");
				for (int i=0; i<32; i++) fprintf(c->errf, "%.2X", pkey_sha256[i]);
				fprintf(c->errf, "\n");
			} else {
				if (c->chain_idx)
					fprintf(c->errf, "Accepted trust anchor certificate at position %d matching DANE record:\n", c->chain_idx);
				else
					fprintf(c->errf, "Accepted end entity certificate matching DANE record:\n");
				print_tlsa(c->errf, c->tlsa, c->tlsa_len, r);
			}
		}
	}
	c->chain_idx++;
}

static unsigned end_chain(const br_x509_class **ctx)
{
	struct x509_dane_context *c = (void *)ctx;
	if (c->ee_pkey) return 0;
	unsigned r = c->minimal.vtable->end_chain(&c->minimal.vtable);
	if (r && r != BR_ERR_X509_NOT_TRUSTED) return r;
	return c->trusted ? 0 : BR_ERR_X509_NOT_TRUSTED;
}

static const br_x509_pkey *get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
	struct x509_dane_context *c = (void *)ctx;
	if (c->ee_pkey) {
		if (usages) *usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN; // ??
		return c->ee_pkey;
	}
	return c->minimal.vtable->get_pkey(&c->minimal.vtable, usages);
}

static const br_x509_class x509_dane_vtable = {
	.context_size = sizeof(struct x509_dane_context),
	.start_chain = start_chain,
	.start_cert = start_cert,
	.append = append,
	.end_cert = end_cert,
	.end_chain = end_chain,
	.get_pkey = get_pkey,
};

struct vt_wrap {
	br_x509_class vt;
	unsigned (*old_end_chain)(const br_x509_class **ctx);
	const unsigned char *tlsa;
	size_t tlsa_len;
};

static void *tlsthread(void *vc)
{
	struct start_ctx *ctx = vc;
	int s = ctx->s, p = ctx->p;

	br_ssl_client_context sc;
	struct x509_dane_context xc = {
		.vtable = &x509_dane_vtable,
		.tlsa = ctx->tlsa,
		.tlsa_len = ctx->tlsa_len,
		.errf = ctx->errf,
	};
	br_ssl_client_init_full(&sc, &xc.minimal, 0, 0);
	br_ssl_engine_set_x509(&sc.eng, &xc.vtable);

	unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
	br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);

	br_ssl_client_reset(&sc, ctx->hostname, 0);

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
