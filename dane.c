#include <bearssl.h>
#include <string.h>
#include <arpa/nameser.h>

static size_t lenlen(size_t k)
{
	if (k>=65536) return 4;
	if (k>=256) return 3;
	if (k>=128) return 2;
	return 1;
}

static size_t derlen(size_t k)
{
	return 1+lenlen(k)+k;
}

static size_t encode(unsigned char *buf, int type, size_t len)
{
	buf[0] = type;
	if (lenlen(len)==4) {
		buf[1] = 0x83;
		buf[2] = len>>16;
		buf[3] = len>>8;
		buf[4] = len;
	} else if (lenlen(len)==3) {
		buf[1] = 0x82;
		buf[2] = len>>8;
		buf[3] = len;
	} else if (lenlen(len)==2) {
		buf[1] = 0x81;
		buf[2] = len;
	} else {
		buf[1] = len;
	}
	return lenlen(len)+1;
}

static void hash_rsa(void *ctx, void (*update)(void *, const void *, size_t), unsigned char *n, size_t nlen, unsigned char *e, size_t elen)
{
	while (nlen && !*n) nlen--, n++;
	while (elen && !*e) elen--, e++;
	size_t encoded_elen = derlen(elen+(e[0]>127));
	size_t encoded_nlen = derlen(nlen+(n[0]>127));
	size_t encoded_k_seq_len = derlen(encoded_elen+encoded_nlen);
	size_t encoded_k_bs_len = derlen(encoded_k_seq_len+1);

	unsigned char buf[5];

	// seq
	update(ctx, buf, encode(buf, 0x30, 15+encoded_k_bs_len));

	// seq->objid,null
	update(ctx, "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00", 15);

	// bitstring
	update(ctx, buf, encode(buf, 0x03, 1+encoded_k_seq_len));
	update(ctx, "\x00", 1);

	// seq
	update(ctx, buf, encode(buf, 0x30, encoded_nlen + encoded_elen));

	// int
	update(ctx, buf, encode(buf, 0x02, nlen+(n[0]>127)));
	if (n[0]>127) update(ctx, "\x00", 1);
	update(ctx, n, nlen);

	// int
	update(ctx, buf, encode(buf, 0x02, elen+(e[0]>127)));
	if (e[0]>127) update(ctx, "\x00", 1);
	update(ctx, e, elen);
}

const unsigned char *br_get_curve_OID(int);

static void hash_ec(void *ctx, void (*update)(void *, const void *, size_t), int curve, unsigned char *q, size_t qlen)
{
	size_t encoded_qlen = derlen(qlen+1);
	const unsigned char *oid = br_get_curve_OID(curve);
	if (!oid) oid = (unsigned char *)"";
	size_t encoded_oidlen = derlen(oid[0]);
	size_t encoded_seq_len = derlen(9+encoded_oidlen+encoded_qlen);

	unsigned char buf[5];

	// seq
	update(ctx, buf, encode(buf, 0x30, encoded_seq_len));

	// seq
	update(ctx, buf, encode(buf, 0x30, 9+encoded_oidlen));

	// oid
	update(ctx, "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01", 9);

	// oid
	update(ctx, "\x06", 1);
	update(ctx, oid, oid[0]+1);

	// int
	update(ctx, buf, encode(buf, 0x03, qlen+1));
	update(ctx, "", 1);
	update(ctx, q, qlen);
}

struct cmpctx {
	const unsigned char *data;
	size_t len;
	int mismatch;
};

static void cmpupdate(void *c, const void *b, size_t l)
{
	struct cmpctx *ctx = c;;
	const unsigned char *s = b;
	if (l > ctx->len) {
		ctx->len = 0;
		ctx->mismatch = 1;
		return;
	}
	for (size_t i=0; i<l; i++)
		if (s[i] != ctx->data[i]) {
			ctx->mismatch = 1;
			break;
		}
	ctx->data += l;
	ctx->len -= l;
}

static void sha256update(void *c, const void *b, size_t l)
{
	br_sha256_update(c, b, l);
}

static void sha512update(void *c, const void *b, size_t l)
{
	br_sha512_update(c, b, l);
}

static int check_key(const br_x509_pkey *pkey, int match_type, const unsigned char *pin, size_t pinlen)
{
	void (*update)(void *, const void *, size_t);
	union {
		struct cmpctx cmp;
		br_sha256_context sha256;
		br_sha512_context sha512;
	} hc;
	switch (match_type) {
	case 0:
		hc.cmp.data = pin;
		hc.cmp.len = pinlen;
		update = cmpupdate;
		break;
	case 1:
		if (pinlen != 32) return -1;
		br_sha256_init(&hc.sha256);
		update = sha256update;
		break;
	case 2:
		if (pinlen != 64) return -1;
		br_sha512_init(&hc.sha512);
		update = sha512update;
		break;
	default:
		return -1;
	}
	switch (pkey->key_type) {
	case BR_KEYTYPE_RSA:
		hash_rsa(&hc, update, pkey->key.rsa.n, pkey->key.rsa.nlen, pkey->key.rsa.e, pkey->key.rsa.elen);
		break;
	case BR_KEYTYPE_EC:
		hash_ec(&hc, update, pkey->key.ec.curve, pkey->key.ec.q, pkey->key.ec.qlen);
		break;
	default:
		return -1;
	}
	unsigned char out[64];
	switch (match_type) {
	case 0:
		if (!hc.cmp.mismatch) return 0;
		break;
	case 1:
		br_sha256_out(&hc.sha256, out);
		if (!memcmp(pin, out, 32)) return 0;
		break;
	case 2:
		br_sha512_out(&hc.sha512, out);
		if (!memcmp(pin, out, 64)) return 0;
		break;
	default:
		return -1;
	}
	return -1;
}

int check_tlsa(const br_x509_pkey *pkey, const unsigned char *sha256, const unsigned char *sha512, int is_ee, const unsigned char *tlsa, size_t tlsa_len)
{
	ns_msg msg;
	if (ns_initparse(tlsa, tlsa_len, &msg) < 0)
		return -1;
	ns_rr rr;
	for (int i=0; !ns_parserr(&msg, ns_s_an, i, &rr); i++) {
		if (ns_rr_type(rr) != 52) continue;
		if (ns_rr_rdlen(rr) < 4) return -1;
		const unsigned char *pinning = ns_rr_rdata(rr);
		if (!is_ee && (pinning[0] == 3 || pinning[0] == 1))
			continue; // DANE-EE pinnings can't be used for non-EE certs
		if (is_ee && (pinning[0] != 3 && pinning[0] != 1))
			continue; // Only DANE-EE pinnings can be used for EE certs
		if (pinning[1] == 0) {
			if (pinning[2]==0) {
				unsigned char sha256_buf[32];
				br_sha256_context hasher;
				br_sha256_init(&hasher);
				br_sha256_update(&hasher, pinning+3, ns_rr_rdlen(rr)-3);
				br_sha256_out(&hasher, sha256_buf);
				if (!memcmp(sha256_buf, sha256, 32))
					return 0;
			} else if (pinning[2]==1) {
				if (ns_rr_rdlen(rr)-3 != 32) continue;
				if (!memcmp(pinning+3, sha256, 32))
					return 0;
			} else if (pinning[2]==2) {
				if (ns_rr_rdlen(rr)-3 != 64) continue;
				if (!memcmp(pinning+3, sha512, 64))
					return 0;
			}
		} else if (pinning[1] == 1) {
			if (!check_key(pkey, pinning[2], pinning+3, ns_rr_rdlen(rr)-3))
				return 0;
		}
	}
	return -1;
}
