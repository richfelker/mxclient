#include <bearssl.h>
#include <string.h>
#include <arpa/nameser.h>

int check_tlsa(const unsigned char *pkey_sha256, const unsigned char *pkey_sha512,
	const unsigned char *cert_sha256, const unsigned char *cert_sha512,
	int is_ee, const unsigned char *tlsa, size_t tlsa_len)
{
	if (!tlsa_len) return 0;

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

		unsigned char rewritten_cad_buf[32];
		const unsigned char *cad = pinning+3;
		size_t cad_len = ns_rr_rdlen(rr)-3;

		int match_type = pinning[2];
		if (match_type == 0) {
			// rewrite match type 0 (full key/cert copy) as sha256
			br_sha256_context hasher;
			br_sha256_init(&hasher);
			br_sha256_update(&hasher, cad, cad_len);
			br_sha256_out(&hasher, rewritten_cad_buf);
			cad = rewritten_cad_buf;
			cad_len = 32;
			match_type = 1;
		}

		const unsigned char *match_sha256, *match_sha512;
		if (pinning[1] == 0) {
			match_sha256 = cert_sha256;
			match_sha512 = cert_sha512;
		} else {
			match_sha256 = pkey_sha256;
			match_sha512 = pkey_sha512;
		}
		if (match_type==1) {
			if (cad_len != 32) continue;
			if (!memcmp(cad, match_sha256, 32))
				return i;
		} else if (match_type==2) {
			if (cad_len != 64) continue;
			if (!memcmp(cad, match_sha512, 64))
				return i;
		}
	}
	return -1;
}
