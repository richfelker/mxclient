# mxclient

mxclient is not a normal MTA. Rather, it's a minimalist client for
sending mail *direct to the recipient's MX*, or mail exchanger, in
contrast to the widespread practice of sending through a "smarthost"
or "outgoing mail server".

In combination with sufficient cryptographic measures, this ensures
that no one outside the receiving domain's mail system can intercept
or alter the contents of the message, making mxclient suitable for:

- Private bi-directional communication between individuals (with
  personal domains) or organizations that mutually implement this kind
  of delivery.

- Delivery of sensitive data like account access or password reset
  tokens without them passing through third party mailer systems.

- Avoiding dragnet surveillance of outgoing mail in otherwise
  conventional mail setups.

mxclient is not an outgoing mail queue. It delivers mail
synchronously, to a single recipient, reporting success, temporary
failure, or permanent failure via the exit status (using `sysexits.h`
codes). It can be used as the backend for the separate queuing
frontend to yield a full "sendmail" command for use by MUAs or scripts
that expect asynchronous delivery.

Ability to send mail directly to the recipient's MX depends on having
unblocked outgoing port 25 (many residential and mobile ISPs firewall
it) and on not being on one of several "dialup"/residential IP address
lists that many sites' mail systems use to block likely spammers. To
get around this while still maintaining the security and privacy
properties of interfacing directly with the recipient's MX, future
versions of mxclient will support performing the actual TCP connection
through a (SOCKS5 or `ssh -W` child process) proxy while keeping the
actual TLS endpoint local.


## Project Status

mxclient is incomplete but under active development. Proxy support is
missing, and DANE modes other than DANE-EE with public key only (vs
full cert) are untested. Otherwise all basic functionality is present.


## Background on SMTP and TLS

SMTP does not use a separate port/service for TLS-encrypted sessions,
but rather a "STARTTLS" command, advertised in the greeting response,
to upgrade a connection to TLS. Originally this provided only
opportunistic encryption that was easily stripped by MITM devices, and
provided no authentication of the server to the client. Since the CA
infrastructure used on the web does not carry over to SMTP, mail
servers generally used self-signed certificates.

With DANE and DNSSEC, however, it's possible to have a full chain of
trust for the intended recipient domain. In short, DANE publishes key
or certificate pinnings for a domain in DNS records, and DNSSEC
provides a signature chain proving the authenticity of both the DANE
records and the conventional record types used for mail (MX for the
domain's mail exchangers, and A/AAAA/CNAME records used to find the IP
address of the server to send to).

mxclient uses the SMTP STARTTLS extension whenever it is advertised by
the server or DANE is in use for the domain, and enforces DANE-EE
unless it can determine non-existence of TLSA (DANE) records for the
recipient domain's MX. It relies on a local DNSSEC-validating
nameserver, ideally on localhost, to obtain this information.


## Building

The only dependencies for mxclient are
[BearSSL](https://www.bearssl.org/) and a libc with the
`arpa/nameser.h` and `res_query` interfaces. Drop-in replacements for
these can be used on systems that don't have them.

A `config.mak` file can be created to override default compile/link
flags or install paths. Future versions will ship a `configure` script
that can generate a `config.mak` for you.

After checking and adusting config as needed, simply run `make`.
mxclient can be installed with `make install`, but installation is not
needed to use it. The program is entirely self-contained and
stand-alone.


## Usage

Basic usage is:

    mxclient -f you@your.example.com them@their.example.com < message

where `message` *should* be in standard RFC 822/2822 email message
form, but is not processed locally by mxclient. In particular, a line
containing a lone `.` is not special; input ends only at EOF (like
sendmail with the `-i` option). Either ordinary newlines or CR/LF line
endings (or any mix) are accepted.

mxclient accepts (and mostly ignores) a few common `sendmail` command
line options, including `-F`, `-i`, and `-o*`. The only option it
actually uses is `-f`, to set the envelope sender (for the `MAIL
FROM:` command).

Exit code will be 75 for temporary/retryable errors, and another (from
among `sysexits.h` codes) nonzero value for non-retryable errors, or
zero for success. During operation, progress is printed to `stdout`.
