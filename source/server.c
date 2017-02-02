#include <stdlib.h>
#include <stdio.h>
#include "server.h"

#pragma comment(lib, "websockets_static.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "Ws2_32.lib")

client_t *client_insert(client_t **head, lws *socket) {
	client_t *client = (server_client_t *)malloc(sizeof(server_client_t));
	client->socket = socket;
	client->next = *head;
	*head = client;
	return client;
}

void client_remove(client_t **head, lws *socket) {
	for (client_t **current = head; *current; current = &(*current)->next) {
		if ((*current)->socket == socket) {
			client_t* next = (*current)->next;
			free(*current);
			*current = next;
			break;
		}
	}
}


static int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);
static int callback_websockets(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);

static struct lws_protocols server_protocols[] = {
	{ "http-only", callback_http, sizeof(struct per_session_data__http), 0 },
	{ "dumb-increment-protocol", callback_websockets, sizeof(struct per_session_data__dumb_increment), 1024 * 1024 },
	{ NULL, NULL, 0, 0 /* End of list */ }
};

static server_t *self = NULL;

server_t *server_create(int port, size_t buffer_size, int use_ssl) {
	self = (server_t *)malloc(sizeof(server_t));
	memset(self, 0, sizeof(server_t));

	self->buffer_size = buffer_size;
	size_t full_buffer_size = LWS_SEND_BUFFER_PRE_PADDING + buffer_size + LWS_SEND_BUFFER_POST_PADDING;
	self->send_buffer_with_padding = (unsigned char *)malloc(full_buffer_size);
	self->send_buffer = &self->send_buffer_with_padding[LWS_SEND_BUFFER_PRE_PADDING];

	self->port = port;
	self->clients = NULL;

	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO | LLL_DEBUG | LLL_CLIENT | LLL_PARSER | LLL_HEADER, NULL);

	struct lws_context_creation_info info = { 0 };
	info.port = port;
	info.gid = -1;
	info.uid = -1;
	info.user = (void *)self;
	info.protocols = server_protocols;
	info.ssl_cert_filepath = NULL;
	info.ssl_private_key_filepath = NULL;
	if (use_ssl) {
		info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
		info.ssl_cert_filepath = "jsmpeg-vnc.pem";
		info.ssl_private_key_filepath = "jsmpeg-vnc.key.pem";
		//info.ssl_ca_filepath = "jsmpeg-vnc.crt";
	}
	info.ssl_cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:"
		"ECDHE-RSA-AES256-GCM-SHA384:"
		"DHE-RSA-AES256-GCM-SHA384:"
		"ECDHE-RSA-AES256-SHA384:"
		"HIGH:!aNULL:!eNULL:!EXPORT:"
		"!DES:!MD5:!PSK:!RC4:!HMAC_SHA1:"
		"!SHA1:!DHE-RSA-AES128-GCM-SHA256:"
		"!DHE-RSA-AES128-SHA256:"
		"!AES128-GCM-SHA256:"
		"!AES128-SHA256:"
		"!DHE-RSA-AES256-SHA256:"
		"!AES256-GCM-SHA384:"
		"!AES256-SHA256";
	self->context = lws_create_context(&info);

	if (!self->context) {
		server_destroy(self);
		return NULL;
	}

	return self;
}

void server_destroy(server_t *self) {
	if (self == NULL) { return; }

	if (self->context) {
		lws_context_destroy(self->context);
	}

	free(self->send_buffer_with_padding);
	free(self);
}

char *server_get_host_address(server_t *self) {
	char host_name[80];
	hostent *host;
	if (
		gethostname(host_name, sizeof(host_name)) == SOCKET_ERROR ||
		!(host = gethostbyname(host_name))
		) {
		return "127.0.0.1";
	}

	return inet_ntoa(*(IN_ADDR *)(host->h_addr_list[0]));
}

char *server_get_client_address(server_t *self, lws *wsi) {
	static char ip_buffer[32];
	static char name_buffer[32];

	lws_get_peer_addresses(
		wsi, lws_get_socket_fd(wsi),
		name_buffer, sizeof(name_buffer),
		ip_buffer, sizeof(ip_buffer)
		);
	return ip_buffer;
}

void server_update(server_t *self) {
	lws_callback_on_writable_all_protocol(self->context, &(server_protocols[1]));
	lws_service(self->context, 0);
}

void server_send(server_t *self, lws *socket, void *data, size_t size, server_data_type_t type) {
	// Caution, this may explode! The lws docs advise against ever calling lws_write()
	// outside of LWS_CALLBACK_SERVER_WRITEABLE. Honoring this advise would complicate things quite
	// a bit - and it seems to work just fine on my system as it is anyway.
	// This won't work reliably on mobile systems where network buffers are typically much smaller.
	// ¯\_(ツ)_/¯

	if (size > self->buffer_size) {
		printf("Cant send %d bytes; exceeds buffer size (%d bytes)\n", size, self->buffer_size);
		return;
	}
	memcpy(self->send_buffer, data, size);
	lws_write(socket, self->send_buffer, size, (lws_write_protocol)type);
}

void server_broadcast(server_t *self, void *data, size_t size, server_data_type_t type) {
	if (size > self->buffer_size) {
		printf("Cant send %d bytes; exceeds buffer size (%d bytes)\n", size, self->buffer_size);
		return;
	}
	memcpy(self->send_buffer, data, size);

	client_foreach(self->clients, client) {
		lws_write(client->socket, self->send_buffer, size, (lws_write_protocol)type);
	}
	lws_callback_on_writable_all_protocol(self->context, &(server_protocols[1]));
}

static int callback_websockets(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
	//server_t *self = (server_t *)lws_context_user(context);

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		client_insert(&self->clients, wsi);

		if (self->on_connect) {
			self->on_connect(self, wsi);
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		if (self->on_message) {
			self->on_message(self, wsi, in, len);
		}
		break;

	case LWS_CALLBACK_CLOSED:
		client_remove(&self->clients, wsi);

		if (self->on_close) {
			self->on_close(self, wsi);
		}
		break;
	}

	return 0;
}

static int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
	//server_t *self = (server_t *)lws_context_user(context);

	if (reason == LWS_CALLBACK_HTTP) {
		if (self->on_http_req && self->on_http_req(self, wsi, (char *)in)) {
			return 0;
		}
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
		return 0;
	}

	return 0;
}
