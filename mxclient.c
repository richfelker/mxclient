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

static int open_mx_socket(const char *domain, char *hostname)
{
	if (strlen(domain) >= HOST_NAME_MAX) return -1;

	unsigned char abuf[512];
	int alen = res_query(domain, 1, T_MX, abuf, sizeof abuf);
	if (alen < 0) return -EX_TEMPFAIL;

	ns_msg msg;
	int r = ns_initparse(abuf, alen, &msg);
	if (r<0) return -EX_TEMPFAIL;
	ns_rr rr;
	if (ns_msg_getflag(msg, ns_f_rcode) == ns_r_nxdomain)
		return -EX_NOHOST;
	if (!ns_msg_count(msg, ns_s_an) && !ns_msg_getflag(msg, ns_f_rcode)) {
		strcpy(hostname, domain);
		int s = open_smtp_socket(hostname);
		return s;
	}
	for (int i=0; !ns_parserr(&msg, ns_s_an, i, &rr); i++) {
		if (ns_rr_type(rr) != T_MX) continue;
		r = ns_name_uncompress(abuf, abuf+alen, ns_rr_rdata(rr)+2, hostname, HOST_NAME_MAX+1);
		if (r<0) return -EX_TEMPFAIL;
		int s = open_smtp_socket(hostname);
		if (s>=0) return s;
	}
	return -EX_TEMPFAIL;
}

static int get_tlsa(unsigned char *tlsa, size_t maxsize, const char *hostname)
{
	char buf[HOST_NAME_MAX+20];
	snprintf(buf, sizeof buf, "_25._tcp.%s", hostname);
	int alen = res_query(buf, 1, 52 /* TLSA */, tlsa, maxsize);
	if (alen < 0) return -EX_TEMPFAIL;

	ns_msg msg;
	int r = ns_initparse(tlsa, alen, &msg);
	if (r<0) return 0;
	ns_rr rr;
	if (ns_msg_getflag(msg, ns_f_rcode) == ns_r_nxdomain)
		return 0;
	if (ns_msg_getflag(msg, ns_f_rcode) != ns_r_noerror)
		return -EX_TEMPFAIL;
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

	int tlsa_len = get_tlsa(tlsa, sizeof tlsa, mx_hostname);

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
