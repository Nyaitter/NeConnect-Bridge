/*
 * nctb_hook64.dll
 *
 * NeConnect Bridge が起動したアプリの通信を、ローカルのブリッジ入口
 * (127.0.0.1:NCTB_SOCKS_PORT) 経由に切り替えるための補助モジュール。
 *
 * - 各モジュールの import table を書き換えて connect / 名前解決 / プロセス起動を横取りする
 * - 名前解決はローカルで割り当てた仮のアドレスを返し、接続時に元の名前で送る
 * - 起動した子プロセスにも自分自身を読み込ませる
 * - ループバック・LAN 内・マルチキャストはそのまま通す
 *
 * 64bit 専用。
 */
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define NCTB_MAX_FAKE 4096
#define NCTB_MAX_MODS 1024
#define NCTB_MAX_ALLOC 4096
#define NCTB_CONNECT_TIMEOUT_MS 30000
#define NCTB_MAX_MODULE_REFRESH 400

typedef int (WSAAPI *fn_connect)(SOCKET, const struct sockaddr *, int);
typedef int (WSAAPI *fn_WSAConnect)(SOCKET, const struct sockaddr *, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef INT (WSAAPI *fn_getaddrinfo)(PCSTR, PCSTR, const ADDRINFOA *, PADDRINFOA *);
typedef INT (WSAAPI *fn_GetAddrInfoW)(PCWSTR, PCWSTR, const ADDRINFOW *, PADDRINFOW *);
typedef struct hostent *(WSAAPI *fn_gethostbyname)(const char *);
typedef void (WSAAPI *fn_freeaddrinfo)(PADDRINFOA);
typedef void (WSAAPI *fn_freeaddrinfoW)(PADDRINFOW);
typedef BOOL (WINAPI *fn_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                         BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *fn_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                         BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

static HMODULE g_self = NULL;
static int g_port = 0;
static CRITICAL_SECTION g_lock;

static fn_connect g_connect = NULL;
static fn_WSAConnect g_wsa_connect = NULL;
static fn_getaddrinfo g_getaddrinfo = NULL;
static fn_GetAddrInfoW g_getaddrinfoW = NULL;
static fn_gethostbyname g_gethostbyname = NULL;
static fn_freeaddrinfo g_freeaddrinfo = NULL;
static fn_freeaddrinfoW g_freeaddrinfoW = NULL;
static fn_CreateProcessA g_cpa = NULL;
static fn_CreateProcessW g_cpw = NULL;

typedef struct {
	unsigned int ip; /* host byte order */
	char name[256];
	int used;
} fake_entry;

static fake_entry g_fake[NCTB_MAX_FAKE];
static int g_fake_count = 0;

typedef struct {
	void *a;
	void *b;
	void *c;
	int used;
} alloc_entry;

static alloc_entry g_allocs[NCTB_MAX_ALLOC];
static int g_alloc_count = 0;

static HMODULE g_patched[NCTB_MAX_MODS];
static int g_patched_count = 0;

static int register_alloc(void *a, void *b, void *c);
static int take_alloc(void *a, void **b, void **c);

/* ------------------------------------------------------------------ */
/* 小さなヘルパー                                                     */
/* ------------------------------------------------------------------ */

static int send_all(SOCKET s, const char *buf, int len)
{
	int sent = 0;
	while (sent < len) {
		int n = send(s, buf + sent, len - sent, 0);
		if (n == SOCKET_ERROR) {
			int e = WSAGetLastError();
			if (e == WSAEWOULDBLOCK) {
				Sleep(5);
				continue;
			}
			return -1;
		}
		if (n == 0)
			return -1;
		sent += n;
	}
	return 0;
}

static int recv_all(SOCKET s, char *buf, int len)
{
	int got = 0;
	while (got < len) {
		int n = recv(s, buf + got, len - got, 0);
		if (n == SOCKET_ERROR) {
			int e = WSAGetLastError();
			if (e == WSAEWOULDBLOCK) {
				Sleep(5);
				continue;
			}
			return -1;
		}
		if (n == 0)
			return -1;
		got += n;
	}
	return 0;
}

static int is_ipv4_literal(const char *h)
{
	struct in_addr a;
	return h && inet_pton(AF_INET, h, &a) == 1;
}

static int is_ipv6_literal(const char *h)
{
	struct in6_addr a;
	return h && inet_pton(AF_INET6, h, &a) == 1;
}

/* ローカル/LAN など、そのまま通すべき IPv4 か */
static int v4_is_direct(unsigned int ip /* host order */)
{
	if (ip == 0)
		return 1;
	if ((ip >> 24) == 127)
		return 1;
	if ((ip >> 24) == 10)
		return 1;
	if ((ip >> 24) == 172 && ((ip >> 16) & 0xff) >= 16 && ((ip >> 16) & 0xff) <= 31)
		return 1;
	if ((ip >> 24) == 192 && ((ip >> 16) & 0xff) == 168)
		return 1;
	if ((ip >> 24) == 169 && ((ip >> 16) & 0xff) == 254)
		return 1;
	if ((ip >> 24) == 100 && ((ip >> 16) & 0xff) >= 64 && ((ip >> 16) & 0xff) <= 127)
		return 1; /* キャリア内 NAT */
	if ((ip >> 24) >= 224)
		return 1; /* マルチキャスト・予約 */
	if ((ip >> 24) == 0)
		return 1;
	return 0;
}

static int v6_is_direct(const struct in6_addr *a)
{
	if (IN6_IS_ADDR_LOOPBACK(a))
		return 1;
	if (IN6_IS_ADDR_LINKLOCAL(a))
		return 1;
	if (IN6_IS_ADDR_SITELOCAL(a))
		return 1;
	if (IN6_IS_ADDR_MULTICAST(a))
		return 1;
	if (IN6_IS_ADDR_UNSPECIFIED(a))
		return 1;
	if ((a->s6_bytes[0] & 0xfe) == 0xfc)
		return 1; /* ユニークローカル */
	if (IN6_IS_ADDR_V4MAPPED(a)) {
		unsigned int ip = ((unsigned int)a->s6_bytes[12] << 24) | ((unsigned int)a->s6_bytes[13] << 16) |
		                  ((unsigned int)a->s6_bytes[14] << 8) | (unsigned int)a->s6_bytes[15];
		return v4_is_direct(ip);
	}
	return 0;
}

static unsigned int fake_ip_for(const char *name)
{
	unsigned int ip = 0;
	int i;
	if (!name || !*name)
		return 0;
	EnterCriticalSection(&g_lock);
	for (i = 0; i < g_fake_count; i++) {
		if (g_fake[i].used && strcmp(g_fake[i].name, name) == 0) {
			ip = g_fake[i].ip;
			break;
		}
	}
	if (ip == 0 && g_fake_count < NCTB_MAX_FAKE) {
		/* 198.18.0.0/15 の範囲を順番に使う */
		unsigned int idx = (unsigned int)g_fake_count + 1u;
		ip = 0xC6120000u + idx;
		g_fake[g_fake_count].ip = ip;
		strncpy(g_fake[g_fake_count].name, name, sizeof(g_fake[g_fake_count].name) - 1);
		g_fake[g_fake_count].name[sizeof(g_fake[g_fake_count].name) - 1] = '\0';
		g_fake[g_fake_count].used = 1;
		g_fake_count++;
	}
	LeaveCriticalSection(&g_lock);
	return ip;
}

static const char *fake_name_for(unsigned int ip)
{
	const char *res = NULL;
	int i;
	EnterCriticalSection(&g_lock);
	for (i = 0; i < g_fake_count; i++) {
		if (g_fake[i].used && g_fake[i].ip == ip) {
			res = g_fake[i].name;
			break;
		}
	}
	LeaveCriticalSection(&g_lock);
	return res;
}

/* 使わなくなった枠を再利用する。埋まったら 0 を返し、呼び出し側は元の解決に戻す。 */
static int register_alloc(void *a, void *b, void *c)
{
	int i;
	int slot = -1;
	EnterCriticalSection(&g_lock);
	for (i = 0; i < g_alloc_count; i++) {
		if (!g_allocs[i].used) {
			slot = i;
			break;
		}
	}
	if (slot < 0 && g_alloc_count < NCTB_MAX_ALLOC)
		slot = g_alloc_count++;
	if (slot >= 0) {
		g_allocs[slot].a = a;
		g_allocs[slot].b = b;
		g_allocs[slot].c = c;
		g_allocs[slot].used = 1;
	}
	LeaveCriticalSection(&g_lock);
	return slot >= 0;
}

static int take_alloc(void *a, void **b, void **c)
{
	int i;
	int found = 0;
	EnterCriticalSection(&g_lock);
	for (i = 0; i < g_alloc_count; i++) {
		if (g_allocs[i].used && g_allocs[i].a == a) {
			*b = g_allocs[i].b;
			*c = g_allocs[i].c;
			g_allocs[i].used = 0;
			found = 1;
			break;
		}
	}
	LeaveCriticalSection(&g_lock);
	return found;
}

/* 名前解決を横取りすべきか（IP 直指定・localhost・LAN 名はそのまま） */
static int should_map_name(const char *node)
{
	size_t len;
	if (!node || !*node)
		return 0;
	if (is_ipv4_literal(node) || is_ipv6_literal(node))
		return 0;
	if (_stricmp(node, "localhost") == 0)
		return 0;
	len = strlen(node);
	if (len > 0 && node[len - 1] == '.')
		return 1;
	if (strchr(node, '.') == NULL)
		return 0; /* 名前だけのホストは LAN 名とみなす */
	if (len >= 6 && _stricmp(node + len - 6, ".local") == 0)
		return 0;
	if (len >= 5 && _stricmp(node + len - 5, ".lan") == 0)
		return 0;
	if (len >= 10 && _stricmp(node + len - 10, ".localhost") == 0)
		return 0;
	return 1;
}

/* ------------------------------------------------------------------ */
/* SOCKS5 ハンドシェイク                                               */
/* ------------------------------------------------------------------ */

static int socks5_handshake(SOCKET s, const char *host, int port, int is_domain)
{
	unsigned char buf[512];
	int p = 0;
	int alen = 0;
	unsigned char rb[4];
	unsigned char tmp[300];

	buf[0] = 5;
	buf[1] = 1;
	buf[2] = 0;
	if (send_all(s, (const char *)buf, 3) != 0)
		return -1;
	if (recv_all(s, (char *)buf, 2) != 0)
		return -1;
	if (buf[0] != 5)
		return -1;

	buf[p++] = 5;
	buf[p++] = 1;
	buf[p++] = 0;
	if (is_domain) {
		int len = (int)strlen(host);
		if (len <= 0 || len > 255)
			return -1;
		buf[p++] = 3;
		buf[p++] = (unsigned char)len;
		memcpy(buf + p, host, len);
		p += len;
	} else {
		struct in_addr a4;
		struct in6_addr a6;
		if (inet_pton(AF_INET, host, &a4) == 1) {
			buf[p++] = 1;
			memcpy(buf + p, &a4, 4);
			p += 4;
		} else if (inet_pton(AF_INET6, host, &a6) == 1) {
			buf[p++] = 4;
			memcpy(buf + p, &a6, 16);
			p += 16;
		} else {
			return -1;
		}
	}
	buf[p++] = (unsigned char)((port >> 8) & 0xff);
	buf[p++] = (unsigned char)(port & 0xff);
	if (send_all(s, (const char *)buf, p) != 0)
		return -1;
	if (recv_all(s, (char *)rb, 4) != 0)
		return -1;
	if (rb[0] != 5 || rb[1] != 0)
		return -1;
	if (rb[3] == 1) {
		alen = 4;
	} else if (rb[3] == 4) {
		alen = 16;
	} else if (rb[3] == 3) {
		unsigned char l = 0;
		if (recv_all(s, (char *)&l, 1) != 0)
			return -1;
		alen = (int)l;
	} else {
		return -1;
	}
	if (alen > 0 && recv_all(s, (char *)tmp, alen) != 0)
		return -1;
	if (recv_all(s, (char *)tmp, 2) != 0)
		return -1;
	return 0;
}

/* 入口への接続。相手が非同期で使っている場合は、準備できるまで待つ。 */
static int connect_entry(SOCKET s, const struct sockaddr *addr, int len, int *was_nonblocking)
{
	int rc = g_connect(s, addr, len);
	if (rc == 0)
		return 0;
	if (WSAGetLastError() != WSAEWOULDBLOCK)
		return -1;

	*was_nonblocking = 1;
	{
		fd_set wfds;
		fd_set efds;
		struct timeval tv;
		int sel;
		int err = 0;
		int elen = (int)sizeof(err);

		FD_ZERO(&wfds);
		FD_SET(s, &wfds);
		FD_ZERO(&efds);
		FD_SET(s, &efds);
		tv.tv_sec = NCTB_CONNECT_TIMEOUT_MS / 1000;
		tv.tv_usec = 0;
		sel = select(0, NULL, &wfds, &efds, &tv);
		if (sel <= 0)
			return -1;
		if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &elen) != 0 || err != 0)
			return -1;
	}
	return 0;
}

static int redirect_socket(SOCKET s, const char *host, int port, int is_domain, int family)
{
	struct sockaddr_in local4;
	struct sockaddr_in6 local6;
	u_long mode = 0;
	u_long nonblock = 1;
	DWORD timeout = NCTB_CONNECT_TIMEOUT_MS;
	DWORD old_recv = 0;
	DWORD old_send = 0;
	int recv_len = (int)sizeof(old_recv);
	int send_len = (int)sizeof(old_send);
	int was_nonblocking = 0;
	int rc;

	if (g_port <= 0)
		return -1;

	memset(&local4, 0, sizeof(local4));
	memset(&local6, 0, sizeof(local6));
	local4.sin_family = AF_INET;
	local4.sin_port = htons((unsigned short)g_port);
	local4.sin_addr.s_addr = htonl(0x7f000001u);
	local6.sin6_family = AF_INET6;
	local6.sin6_port = htons((unsigned short)g_port);
	local6.sin6_addr.s6_bytes[10] = 0xff;
	local6.sin6_addr.s6_bytes[11] = 0xff;
	local6.sin6_addr.s6_bytes[12] = 127;
	local6.sin6_addr.s6_bytes[15] = 1;

	if (family == AF_INET6)
		rc = connect_entry(s, (const struct sockaddr *)&local6, (int)sizeof(local6), &was_nonblocking);
	else
		rc = connect_entry(s, (const struct sockaddr *)&local4, (int)sizeof(local4), &was_nonblocking);

	if (rc == 0) {
		/* 手順の間だけ応答待ちに上限を置く。終わったら元の設定に戻す。 */
		getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&old_recv, &recv_len);
		getsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&old_send, &send_len);
		if (was_nonblocking)
			ioctlsocket(s, FIONBIO, &mode);
		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
		setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));

		rc = socks5_handshake(s, host, port, is_domain);

		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&old_recv, sizeof(old_recv));
		setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&old_send, sizeof(old_send));
		if (was_nonblocking)
			ioctlsocket(s, FIONBIO, &nonblock);
	}

	if (rc != 0) {
		WSASetLastError(WSAECONNREFUSED);
		return SOCKET_ERROR;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* 横取りする関数                                                     */
/* ------------------------------------------------------------------ */

static int WSAAPI hook_connect(SOCKET s, const struct sockaddr *name, int namelen)
{
	char host[256];
	int port = 0;
	int is_domain = 0;
	int family;

	if (!name || g_port <= 0)
		return g_connect(s, name, namelen);

	if (name->sa_family == AF_INET && namelen >= (int)sizeof(struct sockaddr_in)) {
		const struct sockaddr_in *in = (const struct sockaddr_in *)name;
		unsigned int ip = ntohl(in->sin_addr.s_addr);
		const char *fname;
		port = ntohs(in->sin_port);
		family = AF_INET;
		fname = fake_name_for(ip);
		if (fname) {
			strncpy(host, fname, sizeof(host) - 1);
			host[sizeof(host) - 1] = '\0';
			is_domain = 1;
		} else {
			struct in_addr a;
			a.s_addr = in->sin_addr.s_addr;
			if (!inet_ntop(AF_INET, &a, host, sizeof(host)))
				return g_connect(s, name, namelen);
			if (v4_is_direct(ip))
				return g_connect(s, name, namelen);
		}
	} else if (name->sa_family == AF_INET6 && namelen >= (int)sizeof(struct sockaddr_in6)) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)name;
		family = AF_INET6;
		port = ntohs(in6->sin6_port);
		if (v6_is_direct(&in6->sin6_addr))
			return g_connect(s, name, namelen);
		if (!inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host)))
			return g_connect(s, name, namelen);
	} else {
		return g_connect(s, name, namelen);
	}

	if (port <= 0)
		return g_connect(s, name, namelen);
	return redirect_socket(s, host, port, is_domain, family);
}

static int WSAAPI hook_WSAConnect(SOCKET s, const struct sockaddr *name, int namelen, LPWSABUF callerdata,
                                  LPWSABUF callee_data, LPQOS sqos, LPQOS gqos)
{
	if (g_port > 0 && name && (name->sa_family == AF_INET || name->sa_family == AF_INET6))
		return hook_connect(s, name, namelen);
	return g_wsa_connect(s, name, namelen, callerdata, callee_data, sqos, gqos);
}

static int fill_addrinfo(const char *node, unsigned short port, const ADDRINFOA *hints, PADDRINFOA *res)
{
	unsigned int ip = fake_ip_for(node);
	struct sockaddr_in *sa;
	ADDRINFOA *ai;
	char *canon;

	if (ip == 0)
		return -1;
	sa = (struct sockaddr_in *)calloc(1, sizeof(struct sockaddr_in));
	ai = (ADDRINFOA *)calloc(1, sizeof(ADDRINFOA));
	canon = (char *)calloc(1, strlen(node) + 1);
	if (!sa || !ai || !canon) {
		free(sa);
		free(ai);
		free(canon);
		return -1;
	}
	sa->sin_family = AF_INET;
	sa->sin_port = htons(port);
	sa->sin_addr.s_addr = htonl(ip);
	memcpy(canon, node, strlen(node));
	ai->ai_family = AF_INET;
	ai->ai_socktype = (hints && hints->ai_socktype) ? hints->ai_socktype : SOCK_STREAM;
	ai->ai_protocol = (hints && hints->ai_protocol) ? hints->ai_protocol : IPPROTO_TCP;
	ai->ai_addrlen = sizeof(struct sockaddr_in);
	ai->ai_addr = (struct sockaddr *)sa;
	ai->ai_canonname = canon;
	ai->ai_next = NULL;
	if (!register_alloc(ai, sa, canon)) {
		free(sa);
		free(ai);
		free(canon);
		return -1;
	}
	*res = ai;
	return 0;
}

/* 仮の IPv4 を返してよい相手か。IPv6 だけを求める呼び出しはそのまま任せる。 */
static int hints_accept_ipv4(const ADDRINFOA *hints)
{
	if (!hints)
		return 1;
	return hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET;
}

static int hints_accept_ipv4w(const ADDRINFOW *hints)
{
	if (!hints)
		return 1;
	return hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET;
}

static int WSAAPI hook_getaddrinfo(PCSTR node, PCSTR service, const ADDRINFOA *hints, PADDRINFOA *res)
{
	int port = 0;
	if (g_port > 0 && res && node && service && should_map_name(node) && hints_accept_ipv4(hints) &&
	    (!hints || (hints->ai_socktype != SOCK_DGRAM && hints->ai_socktype != SOCK_RAW))) {
		port = atoi(service);
		if (port > 0 && port < 65536 && fill_addrinfo(node, (unsigned short)port, hints, res) == 0)
			return 0;
		if ((!service || !*service) && fill_addrinfo(node, (unsigned short)port, hints, res) == 0)
			return 0;
	}
	return g_getaddrinfo(node, service, hints, res);
}

static int WSAAPI hook_GetAddrInfoW(PCWSTR node, PCWSTR service, const ADDRINFOW *hints, PADDRINFOW *res)
{
	char nodeA[256];
	char serviceA[32];
	if (g_port > 0 && res && node && service && hints_accept_ipv4w(hints) &&
	    (!hints || (hints->ai_socktype != SOCK_DGRAM && hints->ai_socktype != SOCK_RAW))) {
		int i;
		for (i = 0; i < (int)sizeof(nodeA) - 1 && node[i]; i++)
			nodeA[i] = (char)node[i];
		nodeA[i] = '\0';
		for (i = 0; i < (int)sizeof(serviceA) - 1 && service[i]; i++)
			serviceA[i] = (char)service[i];
		serviceA[i] = '\0';
		if (should_map_name(nodeA)) {
			int port = atoi(serviceA);
			if (port > 0 && port < 65536) {
				unsigned int ip = fake_ip_for(nodeA);
				if (ip != 0) {
					struct sockaddr_in *sa = (struct sockaddr_in *)calloc(1, sizeof(struct sockaddr_in));
					ADDRINFOW *ai = (ADDRINFOW *)calloc(1, sizeof(ADDRINFOW));
					wchar_t *canon = (wchar_t *)calloc(256, sizeof(wchar_t));
					if (sa && ai && canon) {
						sa->sin_family = AF_INET;
						sa->sin_port = htons((unsigned short)port);
						sa->sin_addr.s_addr = htonl(ip);
						ai->ai_family = AF_INET;
						ai->ai_socktype = (hints && hints->ai_socktype) ? hints->ai_socktype : SOCK_STREAM;
						ai->ai_protocol = (hints && hints->ai_protocol) ? hints->ai_protocol : IPPROTO_TCP;
						ai->ai_addrlen = sizeof(struct sockaddr_in);
						ai->ai_addr = (struct sockaddr *)sa;
						ai->ai_canonname = canon;
						MultiByteToWideChar(CP_ACP, 0, nodeA, -1, canon, 255);
						if (register_alloc(ai, sa, canon)) {
							*res = ai;
							return 0;
						}
					}
					free(sa);
					free(ai);
					free(canon);
				}
			}
		}
	}
	return g_getaddrinfoW(node, service, hints, res);
}

static void WSAAPI hook_freeaddrinfo(PADDRINFOA p)
{
	void *b = NULL;
	void *c = NULL;
	if (p && take_alloc(p, &b, &c)) {
		free(b);
		free(c);
		free(p);
		return;
	}
	if (g_freeaddrinfo)
		g_freeaddrinfo(p);
}

static void WSAAPI hook_freeaddrinfoW(PADDRINFOW p)
{
	void *b = NULL;
	void *c = NULL;
	if (p && take_alloc(p, &b, &c)) {
		free(b);
		free(c);
		free(p);
		return;
	}
	if (g_freeaddrinfoW)
		g_freeaddrinfoW(p);
}

static struct hostent *WSAAPI hook_gethostbyname(const char *name)
{
	static struct hostent he;
	static char *addrs[2];
	static struct in_addr addr;
	unsigned int ip;
	if (g_port > 0 && should_map_name(name)) {
		ip = fake_ip_for(name);
		if (ip != 0) {
			addr.s_addr = htonl(ip);
			addrs[0] = (char *)&addr;
			addrs[1] = NULL;
			he.h_name = (char *)name;
			he.h_aliases = NULL;
			he.h_addrtype = AF_INET;
			he.h_length = 4;
			he.h_addr_list = addrs;
			return &he;
		}
	}
	return g_gethostbyname(name);
}

/* ------------------------------------------------------------------ */
/* 子プロセスへ引き継ぐ                                               */
/* ------------------------------------------------------------------ */

static int inject_self(HANDLE hp)
{
	WCHAR path[MAX_PATH];
	SIZE_T bytes;
	void *mem;
	HMODULE k32;
	void *loadlib;
	HANDLE th;

	if (!hp || hp == INVALID_HANDLE_VALUE)
		return 0;
	if (GetModuleFileNameW(g_self, path, MAX_PATH) <= 0 || !path[0])
		return 0;
	bytes = (wcslen(path) + 1) * sizeof(WCHAR);
	mem = VirtualAllocEx(hp, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!mem)
		return 0;
	if (!WriteProcessMemory(hp, mem, path, bytes, NULL)) {
		VirtualFreeEx(hp, mem, 0, MEM_RELEASE);
		return 0;
	}
	k32 = GetModuleHandleW(L"kernel32.dll");
	if (!k32) {
		VirtualFreeEx(hp, mem, 0, MEM_RELEASE);
		return 0;
	}
	loadlib = (void *)GetProcAddress(k32, "LoadLibraryW");
	if (!loadlib) {
		VirtualFreeEx(hp, mem, 0, MEM_RELEASE);
		return 0;
	}
	th = CreateRemoteThread(hp, NULL, 0, (LPTHREAD_START_ROUTINE)loadlib, mem, 0, NULL);
	if (!th) {
		VirtualFreeEx(hp, mem, 0, MEM_RELEASE);
		return 0;
	}
	WaitForSingleObject(th, 5000);
	CloseHandle(th);
	VirtualFreeEx(hp, mem, 0, MEM_RELEASE);
	return 1;
}

static BOOL WINAPI hook_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                       BOOL inherit, DWORD flags, LPVOID env, LPCWSTR cwd, LPSTARTUPINFOW si,
                                       LPPROCESS_INFORMATION pi)
{
	BOOL ok;
	LPPROCESS_INFORMATION local = pi;
	PROCESS_INFORMATION tmp;
	BOOL use_dummy = 0;
	BOOL was_suspended = (flags & CREATE_SUSPENDED) != 0;

	if (!local) {
		memset(&tmp, 0, sizeof(tmp));
		local = &tmp;
		use_dummy = 1;
	}
	ok = g_cpw(app, cmd, pa, ta, inherit, flags | CREATE_SUSPENDED, env, cwd, si, local);
	if (ok) {
		if (local->hProcess)
			inject_self(local->hProcess);
		/* 呼び出し側が止めたまま起動を求めた場合は、そのままにする。 */
		if (local->hThread && !was_suspended)
			ResumeThread(local->hThread);
		if (use_dummy) {
			if (local->hProcess)
				CloseHandle(local->hProcess);
			if (local->hThread)
				CloseHandle(local->hThread);
		}
	}
	return ok;
}

static BOOL WINAPI hook_CreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                       BOOL inherit, DWORD flags, LPVOID env, LPCSTR cwd, LPSTARTUPINFOA si,
                                       LPPROCESS_INFORMATION pi)
{
	BOOL ok;
	LPPROCESS_INFORMATION local = pi;
	PROCESS_INFORMATION tmp;
	BOOL use_dummy = 0;
	BOOL was_suspended = (flags & CREATE_SUSPENDED) != 0;

	if (!local) {
		memset(&tmp, 0, sizeof(tmp));
		local = &tmp;
		use_dummy = 1;
	}
	ok = g_cpa(app, cmd, pa, ta, inherit, flags | CREATE_SUSPENDED, env, cwd, si, local);
	if (ok) {
		if (local->hProcess)
			inject_self(local->hProcess);
		if (local->hThread && !was_suspended)
			ResumeThread(local->hThread);
		if (use_dummy) {
			if (local->hProcess)
				CloseHandle(local->hProcess);
			if (local->hThread)
				CloseHandle(local->hThread);
		}
	}
	return ok;
}

/* ------------------------------------------------------------------ */
/* import table の書き換え                                            */
/* ------------------------------------------------------------------ */

static int name_is(const char *a, const char *b)
{
	return a && b && _stricmp(a, b) == 0;
}

static void *replacement_for(const char *dll, const char *fn)
{
	if (name_is(dll, "ws2_32.dll")) {
		if (name_is(fn, "connect"))
			return (void *)hook_connect;
		if (name_is(fn, "WSAConnect"))
			return (void *)hook_WSAConnect;
		if (name_is(fn, "getaddrinfo"))
			return (void *)hook_getaddrinfo;
		if (name_is(fn, "GetAddrInfoW"))
			return (void *)hook_GetAddrInfoW;
		if (name_is(fn, "gethostbyname"))
			return (void *)hook_gethostbyname;
		if (name_is(fn, "freeaddrinfo"))
			return (void *)hook_freeaddrinfo;
		if (name_is(fn, "freeaddrinfoW") || name_is(fn, "FreeAddrInfoW"))
			return (void *)hook_freeaddrinfoW;
		return NULL;
	}
	if (name_is(dll, "kernel32.dll")) {
		if (name_is(fn, "CreateProcessW"))
			return (void *)hook_CreateProcessW;
		if (name_is(fn, "CreateProcessA"))
			return (void *)hook_CreateProcessA;
	}
	return NULL;
}

static int is_ws2_module(const char *dll)
{
	if (!dll)
		return 0;
	return name_is(dll, "ws2_32.dll") || name_is(dll, "wsock32.dll");
}

static void patch_module(HMODULE mod)
{
	BYTE *base;
	IMAGE_DOS_HEADER *dos;
	IMAGE_NT_HEADERS64 *nt;
	IMAGE_DATA_DIRECTORY dir;
	IMAGE_IMPORT_DESCRIPTOR *imp;
	int i;

	if (!mod || mod == g_self)
		return;
	base = (BYTE *)mod;
	dos = (IMAGE_DOS_HEADER *)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return;
	nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return;
	dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (dir.VirtualAddress == 0 || dir.Size == 0)
		return;
	imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + dir.VirtualAddress);
	for (i = 0; imp[i].Name != 0; i++) {
		const char *dllname = (const char *)(base + imp[i].Name);
		IMAGE_THUNK_DATA64 *oft;
		IMAGE_THUNK_DATA64 *ft;
		int target_ws2 = is_ws2_module(dllname);
		int target_k32 = name_is(dllname, "kernel32.dll");
		if (!target_ws2 && !target_k32)
			continue;
		oft = (IMAGE_THUNK_DATA64 *)(base + (imp[i].OriginalFirstThunk ? imp[i].OriginalFirstThunk : imp[i].FirstThunk));
		ft = (IMAGE_THUNK_DATA64 *)(base + imp[i].FirstThunk);
		while (oft->u1.Function != 0) {
			if (!(oft->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
				IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)(base + oft->u1.AddressOfData);
				const char *fn = (const char *)ibn->Name;
				void *repl = replacement_for(dllname, fn);
				if (repl) {
					DWORD old = 0;
					if (VirtualProtect(&ft->u1.Function, sizeof(ULONGLONG), PAGE_READWRITE, &old)) {
						ft->u1.Function = (ULONGLONG)(ULONG_PTR)repl;
						VirtualProtect(&ft->u1.Function, sizeof(ULONGLONG), old, &old);
					}
				}
			}
			oft++;
			ft++;
		}
	}
}

static void refresh_modules(void)
{
	HANDLE snap;
	MODULEENTRY32 me;
	int i;

	snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
	if (snap == INVALID_HANDLE_VALUE)
		return;
	me.dwSize = sizeof(me);
	if (Module32First(snap, &me)) {
		do {
			int known = 0;
			for (i = 0; i < g_patched_count; i++) {
				if (g_patched[i] == me.hModule) {
					known = 1;
					break;
				}
			}
			if (!known) {
				if (g_patched_count < NCTB_MAX_MODS) {
					g_patched[g_patched_count++] = me.hModule;
					patch_module(me.hModule);
				}
			}
		} while (Module32Next(snap, &me));
	}
	CloseHandle(snap);
}

static int resolve_reals(void)
{
	HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
	HMODULE k32;
	if (!ws2)
		ws2 = LoadLibraryA("ws2_32.dll");
	if (ws2) {
		g_connect = (fn_connect)GetProcAddress(ws2, "connect");
		g_wsa_connect = (fn_WSAConnect)GetProcAddress(ws2, "WSAConnect");
		g_getaddrinfo = (fn_getaddrinfo)GetProcAddress(ws2, "getaddrinfo");
		g_getaddrinfoW = (fn_GetAddrInfoW)GetProcAddress(ws2, "GetAddrInfoW");
		g_gethostbyname = (fn_gethostbyname)GetProcAddress(ws2, "gethostbyname");
		g_freeaddrinfo = (fn_freeaddrinfo)GetProcAddress(ws2, "freeaddrinfo");
		g_freeaddrinfoW = (fn_freeaddrinfoW)GetProcAddress(ws2, "FreeAddrInfoW");
	}
	k32 = GetModuleHandleW(L"kernel32.dll");
	if (k32) {
		g_cpa = (fn_CreateProcessA)GetProcAddress(k32, "CreateProcessA");
		g_cpw = (fn_CreateProcessW)GetProcAddress(k32, "CreateProcessW");
	}
	return g_connect && g_getaddrinfo;
}

static DWORD WINAPI worker(LPVOID param)
{
	int attempt;
	int passes = 0;

	(void)param;
	Sleep(120);
	/* 読み込み途中のモジュールがあっても、少しずつやり直す。 */
	for (attempt = 0; attempt < 50; attempt++) {
		if (resolve_reals())
			break;
		Sleep(200);
	}
	if (!g_connect || !g_getaddrinfo) {
		g_port = 0; /* 使えないので何もしない */
		return 0;
	}
	for (;;) {
		refresh_modules();
		passes++;
		/* 落ち着いてきたら、見に行く間隔を広げる。 */
		Sleep(passes < 25 ? NCTB_MAX_MODULE_REFRESH : 1500);
	}
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH) {
		WCHAR self[MAX_PATH];
		char port[32];
		HANDLE th;

		(void)reserved;
		g_self = inst;
		DisableThreadLibraryCalls(inst);
		InitializeCriticalSection(&g_lock);

		port[0] = '\0';
		if (GetEnvironmentVariableA("NCTB_SOCKS_PORT", port, sizeof(port)) > 0)
			g_port = atoi(port);

		if (GetModuleFileNameW(inst, self, MAX_PATH) > 0) {
			SetEnvironmentVariableW(L"NCTB_HOOK_DLL", self);
			SetEnvironmentVariableW(L"NCTB_HOOK_READY", L"1");
		}
		th = CreateThread(NULL, 0, worker, NULL, 0, NULL);
		if (th)
			CloseHandle(th);
	}
	return TRUE;
}
