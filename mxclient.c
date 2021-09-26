/*
 * mxclient - a minimalist, direct-to-recipient-mx smtp client
 *
 * Copyright © 2020 Rich Felker
 *
 * SPDX-License-Identifier: MIT
 */

#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <sys/socket.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sysexits.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>

static int open_smtp_socket(const char *hostname)
{
	struct addrinfo *ai, *ai0;
	int r = getaddrinfo(hostname, "25", &(struct addrinfo){.ai_socktype = SOCK_STREAM}, &ai);
	if (r == EAI_NONAME) return -EX_NOHOST;
	if (r) return -EX_TEMPFAIL;
	for (ai0=ai; ai; ai=ai->ai_next) {
		int s = socket(ai->ai_family, ai->ai_socktype|SOCK_CLOEXEC, ai->ai_protocol);
		if (!connect(s, ai->ai_addr, ai->ai_addrlen))
			return s;
		close(s);
	}
	freeaddrinfo(ai0);
	return -EX_TEMPFAIL;
}

int intcmp(const void *pa, const void *pb)
{
	int a = *(const int *)pa;
	int b = *(const int *)pb;
	if (a<b) return -1;
	if (a>b) return 1;
	return 0;
}

static int open_mx_socket(const char *domain, char *hostname)
{
	if (strlen(domain) >= HOST_NAME_MAX) return -1;

	unsigned char qbuf[HOST_NAME_MAX+50];
	unsigned char abuf[512];
	int qlen = res_mkquery(0, domain, 1, T_MX, 0, 0, 0, qbuf, sizeof qbuf);
	if (qlen < 0) return -EX_TEMPFAIL;
	int alen = res_send(qbuf, qlen, abuf, sizeof abuf);
	if (alen < 0) return -EX_TEMPFAIL;

	ns_msg msg;
	int r = ns_initparse(abuf, alen, &msg);
	if (r<0) return -EX_TEMPFAIL;
	ns_rr rr;
	if (ns_msg_getflag(msg, ns_f_rcode) == ns_r_nxdomain)
		return -EX_NOHOST;
	if (ns_msg_getflag(msg, ns_f_rcode))
		return -EX_TEMPFAIL;
	int mxsort[sizeof abuf / 12][2], cnt=0;
	for (int i=0; !ns_parserr(&msg, ns_s_an, i, &rr); i++) {
		if (ns_rr_type(rr) != T_MX) continue;
		mxsort[cnt][0] = ns_rr_rdata(rr)[0]*256 + ns_rr_rdata(rr)[1];
		mxsort[cnt++][1] = i;
	}
	if (!cnt) {
		strcpy(hostname, domain);
		int s = open_smtp_socket(hostname);
		return s;
	}
	qsort(mxsort, cnt, sizeof *mxsort, intcmp);
	for (int i=0; i<cnt; i++) {
		ns_parserr(&msg, ns_s_an, mxsort[i][1], &rr);
		r = ns_name_uncompress(abuf, abuf+alen, ns_rr_rdata(rr)+2, hostname, HOST_NAME_MAX+1);
		if (r<0) return -EX_TEMPFAIL;
		int s = open_smtp_socket(hostname);
		if (s>=0) return s;
	}
	return -EX_TEMPFAIL;
}

static int is_insecure(const char *hostname)
{
	unsigned char query[HOST_NAME_MAX+50];
	unsigned char answer[512];
	int qlen, alen, r;
	ns_msg msg;
	ns_rr rr;
	int rrtype[2] = { 1 /* A */, 5 /* CNAME */ };

	for (int i=0; i<2; i++) {
		qlen = res_mkquery(0, hostname, 1, rrtype[i],
			0, 0, 0, query, sizeof query);
		if (qlen < 0) return 0;
		query[3] |= 32; /* AD flag */

		alen = res_send(query, qlen, answer, sizeof answer);
		if (alen < 0) return 0;

		r = ns_initparse(answer, alen, &msg);
		if (r < 0) return 0;

		r = ns_msg_getflag(msg, ns_f_rcode);
		if (r != ns_r_nxdomain && r != ns_r_noerror) return 0;

		if (ns_msg_getflag(msg, ns_f_ad)) return 0;

		if (rrtype[i] == 5) break;

		int is_cname = 0;
		for (int j=0; !ns_parserr(&msg, ns_s_an, j, &rr); j++)
			if (ns_rr_type(rr) == 5) is_cname = 1;
		if (!is_cname) break;
	}
	return 1;
}

static int get_tlsa(unsigned char *tlsa, size_t maxsize, const char *hostname, FILE *f)
{
	char buf[HOST_NAME_MAX+20];
	snprintf(buf, sizeof buf, "_25._tcp.%s", hostname);
	unsigned char query[HOST_NAME_MAX+50];
	int qlen = res_mkquery(0, buf, 1, 52 /* TLSA */, 0, 0, 0, query, sizeof query);
	if (qlen < 0) return -EX_DATAERR;
	query[3] |= 32; /* AD flag */
	int alen = res_send(query, qlen, tlsa, maxsize);
	if (alen < 0) goto tempfail;

	ns_msg msg;
	int r = ns_initparse(tlsa, alen, &msg);
	if (r<0) goto tempfail;
	ns_rr rr;
	if (ns_msg_getflag(msg, ns_f_rcode) == ns_r_nxdomain)
		return 0;
	if (ns_msg_getflag(msg, ns_f_rcode) != ns_r_noerror) {
		/* in case error is caused by broken auth ns for the domain
		 * failing to understand TLSA query, check to determine
		 * if zone is insecure (unsigned) and conclude no valid
		 * TLSA records */
tempfail:
		if (f) fprintf(f, "%s TLSA lookup failed, checking DNSSEC status\n", hostname);
		if (is_insecure(hostname)) return 0;
		if (f) fprintf(f, "%s cannot be determined insecure; delivery not possible\n", hostname);
		return -EX_TEMPFAIL;
	}
	if (!ns_msg_getflag(msg, ns_f_ad))
		return 0;
	for (int i=0; !ns_parserr(&msg, ns_s_an, i, &rr); i++) {
		if (ns_rr_type(rr) != 52) continue;
		return alen;
	}
	return 0;
}

int starttls_client(int, const char *, const unsigned char *, size_t, FILE *);

#define d2printf(fd, ...) (printf(">>> " __VA_ARGS__), dprintf(fd, __VA_ARGS__))
#define fgets_echo(buf, size, f) (fgets(buf, size, f) ? printf("<<< %s", buf), buf : 0)

int getresponse(char *buf, int size, FILE *f)
{
	do {
		if (!fgets(buf, size, f)) return -1;
		printf("<<< %s", buf);
	} while (!buf[0] || !buf[1] || !buf[2] || buf[3]=='-');
	return 0;
}

int main(int argc, char **argv)
{
	const char *from_addr = "";
	int c;
	while ((c=getopt(argc, argv, "o:F:f:i")) > 0) switch (c) {
	case 'F':
		break;
	case 'f':
		from_addr = optarg;
		break;
	case 'o':
		if (optarg[0] != 'i' || optarg[1]) break;
	case 'i':
		break;
	}

	const char *to = argv[optind];
	if (!to) {
		fprintf(stderr, "%s: missing recipient\n", argv[0]);
		return EX_USAGE;
	}

	signal(SIGPIPE, SIG_IGN);

	int tls = 0, tls_done = 0;
	char mx_hostname[HOST_NAME_MAX+1];
	char helo_host[HOST_NAME_MAX+1];
	unsigned char tlsa[4096];

	gethostname(helo_host, sizeof helo_host);
	const char *domain = strchr(to, '@');
	char buf[1024];
	if (!domain) return EX_USAGE;
	domain++;

	int s = open_mx_socket(domain, mx_hostname);
	if (s < 0) return -s;

	int tlsa_len = get_tlsa(tlsa, sizeof tlsa, mx_hostname, stdout);

	/* failure to obtain DANE records or negative result must be fatal */
	if (tlsa_len < 0) return -tlsa_len;

	/* force tls if there is a tlsa record */
	if (tlsa_len) {
		printf("%s has DANE records, forcing STARTTLS\n", mx_hostname);
		tls = 1;
	} else {
		printf("%s has no DANE records, STARTTLS opportunistic\n", mx_hostname);
	}

	struct timeval timeout = { .tv_sec = 30 };
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);

	FILE *f = fdopen(dup(s), "rb");
	if (getresponse(buf, sizeof buf, f)) goto rderr;
	if (buf[0]!='2') goto fail;

restart:
	if (d2printf(s, "EHLO %s\r\n", helo_host) < 0) goto wrerr;
	for (;;) {
		if (!fgets_echo(buf, sizeof buf, f)) goto rderr;
		if (buf[0]!='2' || !buf[1] || !buf[2] || !buf[3]) goto fail;
		if (!strncmp(buf+4, "STARTTLS", 8)) tls = 1;
		if (buf[3]==' ') break;
	}

	if (tls && !tls_done) {
		if (d2printf(s, "STARTTLS\r\n") < 0) goto wrerr;
		if (getresponse(buf, sizeof buf, f)) goto rderr;
		if (buf[0]!='2') goto fail;

		int tls_s = starttls_client(s, mx_hostname, tlsa, tlsa_len, stdout);
		if (tls_s < 0) {
			printf("STARTTLS failed\n");
			return EX_TEMPFAIL;
		}
		s = tls_s;
		dup2(s, fileno(f));
		tls_done = 1;
		goto restart;
	}

	if (d2printf(s, "MAIL FROM:<%s>\r\n", from_addr) < 0) goto wrerr;
	if (getresponse(buf, sizeof buf, f)) goto rderr;
	if (buf[0]!='2') goto fail;

	if (d2printf(s, "RCPT TO:<%s>\r\n", to) < 0) goto wrerr;
	if (getresponse(buf, sizeof buf, f)) goto rderr;
	if (buf[0]!='2') goto fail;

	if (d2printf(s, "DATA\r\n") < 0) goto wrerr;
	if (getresponse(buf, sizeof buf, f)) goto rderr;
	if (buf[0]!='3') goto fail;

	FILE *f2 = fdopen(dup(s), "wb");
	while (fgets(buf, sizeof buf, stdin)) {
		size_t l = strlen(buf);
		if (l && buf[l-1]=='\n') l--;
		if (l && buf[l-1]=='\r') l--;
		if (buf[0]=='.') putc('.', f2);
		if (fprintf(f2, "%.*s\r\n", (int)l, buf)<0) goto wrerr;
	}
	if (ferror(stdin)) {
		fprintf(stderr, "%s: error reading input: %s\n",
			argv[0], strerror(errno));
	}
	fprintf(f2, ".\r\n");
	if (fclose(f2) < 0) goto wrerr;
	
	if (getresponse(buf, sizeof buf, f)) goto rderr;
	if (buf[0]!='2') goto fail;

	return 0;

fail:
	if (buf[0]=='4') return EX_TEMPFAIL;
	return EX_PROTOCOL;

wrerr:
	fprintf(stderr, "%s: error writing to socket: %s\n",
		argv[0], strerror(errno));
	return EX_TEMPFAIL;

rderr:
	fprintf(stderr, "%s: error reading from socket: %s\n",
		argv[0], strerror(errno));
	return EX_TEMPFAIL;
}
