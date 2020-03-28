#include <bearssl.h>

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

struct hash_ctx {
	br_sha256_context sha256;
	br_sha512_context sha512;	
};

static void hash_update(void *ctx, const void *data, size_t len)
{
	struct hash_ctx *c = ctx;
	br_sha256_update(&c->sha256, data, len);
	br_sha512_update(&c->sha512, data, len);
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

void pkey_hash(unsigned char *sha256, unsigned char *sha512, const br_x509_pkey *pkey)
{
	struct hash_ctx hc;
	br_sha256_init(&hc.sha256);
	br_sha512_init(&hc.sha512);

	switch (pkey->key_type) {
	case BR_KEYTYPE_RSA:
		hash_rsa(&hc, hash_update, pkey->key.rsa.n, pkey->key.rsa.nlen, pkey->key.rsa.e, pkey->key.rsa.elen);
		break;
	case BR_KEYTYPE_EC:
		hash_ec(&hc, hash_update, pkey->key.ec.curve, pkey->key.ec.q, pkey->key.ec.qlen);
		break;
	}
	br_sha256_out(&hc.sha256, sha256);
	br_sha512_out(&hc.sha512, sha512);
}
