#ifndef SERVER_H
#define SERVER_H

#include "libwebsocket/libwebsockets.h"

typedef struct server_client_t {
	lws *socket;
	struct server_client_t *next;
} client_t;

client_t *client_insert(client_t **head, lws *socket);
void client_remove(client_t **head, lws *socket);
#define client_foreach(HEAD, CLIENT) for(client_t *CLIENT = HEAD; CLIENT; CLIENT = CLIENT->next)

typedef enum {
	server_type_text = LWS_WRITE_TEXT,
	server_type_binary = LWS_WRITE_BINARY
} server_data_type_t;

typedef struct server_t {
	lws_context *context;
	size_t buffer_size;
	unsigned char *send_buffer_with_padding;
	unsigned char *send_buffer;
	void *user;

	int port;
	server_client_t *clients;

	void(*on_connect)(server_t *server, lws *wsi);
	void(*on_message)(server_t *server, lws *wsi, void *in, size_t len);
	void(*on_close)(server_t *server, lws *wsi);
	int(*on_http_req)(server_t *server, lws *wsi, char *request);
} server_t;


struct per_session_data__http {
	lws_filefd_type fd;
#ifdef LWS_WITH_CGI
	struct lws_cgi_args args;
#endif
#if defined(LWS_WITH_CGI) || !defined(LWS_NO_CLIENT)
	int reason_bf;
#endif
	unsigned int client_finished : 1;


	struct lws_spa *spa;
	char result[500 + LWS_PRE];
	int result_len;

	char filename[256];
	long file_length;
	lws_filefd_type post_fd;
};

struct per_session_data__dumb_increment {
	int number;
};


server_t *server_create(int port, size_t buffer_size, int use_ssl);
void server_destroy(server_t *self);
char *server_get_host_address(server_t *self);
char *server_get_client_address(server_t *self, lws *wsi);
void server_update(server_t *self);
void server_send(server_t *self, lws *socket, void *data, size_t size, server_data_type_t type);
void server_broadcast(server_t *self, void *data, size_t size, server_data_type_t type);

#endif