/**
 * @file client.c
 * @brief Small bounded HTTP/1.1 client for one-shot byte fetches.
 */

#include "lantern/http/client.h"

#include "lantern/http/core.h"
#include "lantern/support/strings.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

static int parse_port(const char *text, size_t text_len, uint16_t *out_port)
{
    if (!text || text_len == 0 || !out_port)
    {
        return -1;
    }

    uint32_t port = 0;
    for (size_t i = 0; i < text_len; ++i)
    {
        unsigned char ch = (unsigned char)text[i];
        if (!isdigit(ch))
        {
            return -1;
        }
        port = (port * 10u) + (uint32_t)(ch - '0');
        if (port > UINT16_MAX)
        {
            return -1;
        }
    }
    if (port == 0)
    {
        return -1;
    }
    *out_port = (uint16_t)port;
    return 0;
}

void lantern_http_url_reset(struct lantern_http_url *url)
{
    if (!url)
    {
        return;
    }
    free(url->host);
    free(url->path);
    memset(url, 0, sizeof(*url));
}

int lantern_http_url_parse(const char *url, struct lantern_http_url *out_url)
{
    if (!url || !out_url)
    {
        return -1;
    }

    memset(out_url, 0, sizeof(*out_url));
    const char *http_prefix = "http://";
    const char *https_prefix = "https://";
    size_t prefix_len = strlen(http_prefix);
    if (strncasecmp(url, http_prefix, prefix_len) != 0)
    {
        if (strncasecmp(url, https_prefix, strlen(https_prefix)) != 0)
        {
            return -1;
        }
        prefix_len = strlen(https_prefix);
    }

    const char *cursor = url + prefix_len;
    const char *authority_start = cursor;
    while (*cursor && *cursor != '/' && *cursor != '?' && *cursor != '#')
    {
        ++cursor;
    }
    const char *authority_end = cursor;
    if (authority_end <= authority_start)
    {
        return -1;
    }

    out_url->path = *cursor == '/'
                        ? lantern_string_duplicate_len(cursor, strcspn(cursor, "?#"))
                        : lantern_string_duplicate("");
    if (!out_url->path)
    {
        return -1;
    }

    out_url->port = 80;
    if (*authority_start == '[')
    {
        const char *host_start = authority_start + 1;
        const char *host_end = host_start;
        while (host_end < authority_end && *host_end != ']')
        {
            ++host_end;
        }
        if (host_end >= authority_end || host_end == host_start)
        {
            lantern_http_url_reset(out_url);
            return -1;
        }
        out_url->host = lantern_string_duplicate_len(host_start, (size_t)(host_end - host_start));
        const char *port_start = host_end + 1;
        if (!out_url->host
            || (port_start < authority_end
                && (*port_start != ':'
                    || parse_port(
                           port_start + 1,
                           (size_t)(authority_end - port_start - 1),
                           &out_url->port)
                        != 0)))
        {
            lantern_http_url_reset(out_url);
            return -1;
        }
    }
    else
    {
        const char *port_sep = NULL;
        for (const char *p = authority_start; p < authority_end; ++p)
        {
            if (*p == ':')
            {
                port_sep = p;
            }
        }

        const char *host_end = port_sep ? port_sep : authority_end;
        if (host_end <= authority_start)
        {
            lantern_http_url_reset(out_url);
            return -1;
        }
        out_url->host = lantern_string_duplicate_len(
            authority_start,
            (size_t)(host_end - authority_start));
        if (!out_url->host
            || (port_sep
                && parse_port(
                       port_sep + 1,
                       (size_t)(authority_end - port_sep - 1),
                       &out_url->port)
                    != 0))
        {
            lantern_http_url_reset(out_url);
            return -1;
        }
    }

    if (!out_url->host[0])
    {
        lantern_http_url_reset(out_url);
        return -1;
    }
    return 0;
}

static bool header_value_has_token(
    const char *value,
    const char *value_end,
    const char *token)
{
    size_t token_len = strlen(token);
    while (value < value_end)
    {
        while (value < value_end && (*value == ',' || isspace((unsigned char)*value)))
        {
            ++value;
        }
        const char *entry_start = value;
        while (value < value_end && *value != ',')
        {
            ++value;
        }
        const char *entry_end = value;
        while (entry_end > entry_start && isspace((unsigned char)*(entry_end - 1)))
        {
            --entry_end;
        }
        if ((size_t)(entry_end - entry_start) == token_len
            && strncasecmp(entry_start, token, token_len) == 0)
        {
            return true;
        }
        if (value < value_end && *value == ',')
        {
            ++value;
        }
    }
    return false;
}

static const char *find_crlf(const char *start, const char *end)
{
    for (const char *p = start; p + 1 < end; ++p)
    {
        if (p[0] == '\r' && p[1] == '\n')
        {
            return p;
        }
    }
    return NULL;
}

static int parse_status_code(const char *headers, size_t headers_len, int *out_status_code)
{
    if (!headers || !out_status_code)
    {
        return -1;
    }

    const char *headers_end = headers + headers_len;
    const char *line_end = find_crlf(headers, headers_end);
    const char *cursor = headers;
    if (!line_end || line_end - cursor < 10 || memcmp(cursor, "HTTP/", 5u) != 0)
    {
        return -1;
    }
    cursor += 5u;
    if (cursor >= line_end || !isdigit((unsigned char)*cursor))
    {
        return -1;
    }
    while (cursor < line_end && isdigit((unsigned char)*cursor))
    {
        ++cursor;
    }
    if (cursor >= line_end || *cursor++ != '.')
    {
        return -1;
    }
    if (cursor >= line_end || !isdigit((unsigned char)*cursor))
    {
        return -1;
    }
    while (cursor < line_end && isdigit((unsigned char)*cursor))
    {
        ++cursor;
    }
    if (cursor >= line_end || !isspace((unsigned char)*cursor))
    {
        return -1;
    }
    while (cursor < line_end && isspace((unsigned char)*cursor))
    {
        ++cursor;
    }
    if (cursor >= line_end || !isdigit((unsigned char)*cursor))
    {
        return -1;
    }

    int status = 0;
    while (cursor < line_end && isdigit((unsigned char)*cursor))
    {
        status = (status * 10) + (*cursor - '0');
        ++cursor;
    }
    *out_status_code = status;
    return 0;
}

static bool response_is_chunked(const char *headers, size_t headers_len)
{
    static const char HEADER[] = "Transfer-Encoding:";
    const size_t header_len = sizeof(HEADER) - 1u;
    const char *headers_end = headers + headers_len;
    const char *line = find_crlf(headers, headers_end);
    line = line ? line + 2 : headers_end;

    while (line < headers_end)
    {
        const char *line_end = find_crlf(line, headers_end);
        if (!line_end || line_end == line)
        {
            break;
        }
        if ((size_t)(line_end - line) >= header_len
            && strncasecmp(line, HEADER, header_len) == 0)
        {
            const char *value = line + header_len;
            while (value < line_end && isspace((unsigned char)*value))
            {
                ++value;
            }
            if (header_value_has_token(value, line_end, "chunked"))
            {
                return true;
            }
        }
        line = line_end + 2;
    }
    return false;
}

static int copy_body(
    const char *body,
    size_t body_len,
    uint8_t **out_body,
    size_t *out_body_len)
{
    uint8_t *copy = NULL;
    if (body_len > 0)
    {
        copy = malloc(body_len);
        if (!copy)
        {
            return -1;
        }
        memcpy(copy, body, body_len);
    }
    *out_body = copy;
    *out_body_len = body_len;
    return 0;
}

static int decode_chunked_body(
    const char *chunked,
    size_t chunked_len,
    size_t max_body_bytes,
    uint8_t **out_body,
    size_t *out_body_len)
{
    struct lantern_http_buffer decoded = {0};
    size_t cursor = 0;

    while (cursor < chunked_len)
    {
        size_t line_start = cursor;
        while (cursor + 1 < chunked_len && !(chunked[cursor] == '\r' && chunked[cursor + 1] == '\n'))
        {
            ++cursor;
        }
        if (cursor + 1 >= chunked_len || cursor == line_start || cursor - line_start >= 64u)
        {
            goto fail;
        }

        char line[64];
        memcpy(line, chunked + line_start, cursor - line_start);
        line[cursor - line_start] = '\0';
        char *extensions = strchr(line, ';');
        if (extensions)
        {
            *extensions = '\0';
        }

        char *trimmed = line;
        while (*trimmed && isspace((unsigned char)*trimmed))
        {
            ++trimmed;
        }
        errno = 0;
        char *endptr = NULL;
        unsigned long long chunk_size_u64 = strtoull(trimmed, &endptr, 16);
        if (errno != 0 || endptr == trimmed)
        {
            goto fail;
        }
        while (*endptr && isspace((unsigned char)*endptr))
        {
            ++endptr;
        }
        if (*endptr != '\0')
        {
            goto fail;
        }
        cursor += 2u;

        if (chunk_size_u64 == 0)
        {
            if (cursor + 1 < chunked_len && chunked[cursor] == '\r' && chunked[cursor + 1] == '\n')
            {
                break;
            }
            for (size_t i = cursor; i + 3 < chunked_len; ++i)
            {
                if (memcmp(chunked + i, "\r\n\r\n", 4u) == 0)
                {
                    *out_body = (uint8_t *)decoded.data;
                    *out_body_len = decoded.len;
                    memset(&decoded, 0, sizeof(decoded));
                    return 0;
                }
            }
            goto fail;
        }

        if (chunk_size_u64 > (unsigned long long)(chunked_len - cursor)
            || chunk_size_u64 > (unsigned long long)(max_body_bytes - decoded.len))
        {
            goto fail;
        }
        size_t chunk_size = (size_t)chunk_size_u64;
        if (lantern_http_buffer_reserve(&decoded, chunk_size) != 0)
        {
            goto fail;
        }
        memcpy(decoded.data + decoded.len, chunked + cursor, chunk_size);
        decoded.len += chunk_size;
        decoded.data[decoded.len] = '\0';
        cursor += chunk_size;
        if (cursor + 1 >= chunked_len || chunked[cursor] != '\r' || chunked[cursor + 1] != '\n')
        {
            goto fail;
        }
        cursor += 2u;
    }

    *out_body = (uint8_t *)decoded.data;
    *out_body_len = decoded.len;
    memset(&decoded, 0, sizeof(decoded));
    return 0;

fail:
    lantern_http_buffer_free(&decoded);
    return -1;
}

static int extract_response_body(
    const char *response,
    size_t response_len,
    size_t max_body_bytes,
    struct lantern_http_fetch_result *out_result)
{
    const char *body = NULL;
    size_t body_available = 0;
    if (!lantern_http_locate_body(response, response_len, &body, &body_available))
    {
        return LANTERN_HTTP_CLIENT_ERR;
    }

    size_t headers_len = (size_t)(body - response);
    if (parse_status_code(response, headers_len, &out_result->status_code) != 0)
    {
        return LANTERN_HTTP_CLIENT_ERR;
    }
    if (out_result->status_code != 200)
    {
        return LANTERN_HTTP_CLIENT_STATUS_ERROR;
    }

    if (response_is_chunked(response, headers_len))
    {
        return decode_chunked_body(
                   body,
                   body_available,
                   max_body_bytes,
                   &out_result->body,
                   &out_result->body_len)
                   == 0
               ? LANTERN_HTTP_CLIENT_OK
               : LANTERN_HTTP_CLIENT_ERR;
    }

    size_t content_length = 0;
    size_t body_len = body_available;
    if (lantern_http_parse_content_length(response, response_len, &content_length) == 0)
    {
        if (body_available < content_length)
        {
            return LANTERN_HTTP_CLIENT_ERR;
        }
        body_len = content_length;
    }
    if (body_len > max_body_bytes)
    {
        return LANTERN_HTTP_CLIENT_ERR;
    }
    return copy_body(body, body_len, &out_result->body, &out_result->body_len) == 0
               ? LANTERN_HTTP_CLIENT_OK
               : LANTERN_HTTP_CLIENT_ERR;
}

#if defined(_WIN32)
static int connect_tcp(const char *host, uint16_t port)
{
    (void)host;
    (void)port;
    return -1;
}
#else
static int connect_tcp(const char *host, uint16_t port)
{
    char port_text[6];
    int port_written = snprintf(port_text, sizeof(port_text), "%u", (unsigned int)port);
    if (!host || !host[0] || port_written <= 0 || (size_t)port_written >= sizeof(port_text))
    {
        return -1;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *results = NULL;
    if (getaddrinfo(host, port_text, &hints, &results) != 0)
    {
        return -1;
    }

    int fd = -1;
    for (const struct addrinfo *candidate = results; candidate; candidate = candidate->ai_next)
    {
        fd = socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
        if (fd < 0)
        {
            continue;
        }
        if (connect(fd, candidate->ai_addr, candidate->ai_addrlen) == 0)
        {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(results);
    return fd;
}
#endif

static int read_response(
    int fd,
    size_t max_response_bytes,
    struct lantern_http_fetch_result *out_result)
{
    struct lantern_http_buffer response;
    if (lantern_http_buffer_init(&response, 8192u) != 0)
    {
        return LANTERN_HTTP_CLIENT_ERR;
    }

    for (;;)
    {
        char chunk[4096];
#if defined(_WIN32)
        int received = recv(fd, chunk, (int)sizeof(chunk), 0);
#else
        ssize_t received = recv(fd, chunk, sizeof(chunk), 0);
#endif
        if (received < 0)
        {
#if !defined(_WIN32)
            if (errno == EINTR)
            {
                continue;
            }
#endif
            lantern_http_buffer_free(&response);
            return LANTERN_HTTP_CLIENT_ERR;
        }
        if (received == 0)
        {
            break;
        }
        if ((size_t)received > max_response_bytes - response.len
            || lantern_http_buffer_reserve(&response, (size_t)received) != 0)
        {
            lantern_http_buffer_free(&response);
            return LANTERN_HTTP_CLIENT_ERR;
        }
        memcpy(response.data + response.len, chunk, (size_t)received);
        response.len += (size_t)received;
        response.data[response.len] = '\0';
    }

    int rc = response.len == 0
                 ? LANTERN_HTTP_CLIENT_ERR
                 : extract_response_body(response.data, response.len, max_response_bytes, out_result);
    lantern_http_buffer_free(&response);
    return rc;
}

int lantern_http_get_bytes(
    const char *url,
    const char *accept,
    size_t max_response_bytes,
    struct lantern_http_fetch_result *out_result)
{
    if (!url || !out_result || max_response_bytes == 0)
    {
        return LANTERN_HTTP_CLIENT_ERR;
    }
    memset(out_result, 0, sizeof(*out_result));

    struct lantern_http_url parsed;
    if (lantern_http_url_parse(url, &parsed) != 0)
    {
        return LANTERN_HTTP_CLIENT_ERR;
    }
    if (!parsed.path || !parsed.path[0])
    {
        lantern_http_url_reset(&parsed);
        return LANTERN_HTTP_CLIENT_ERR;
    }

    struct lantern_http_buffer request;
    if (lantern_http_buffer_init(&request, 256u) != 0)
    {
        lantern_http_url_reset(&parsed);
        return LANTERN_HTTP_CLIENT_ERR;
    }

    const char *accept_value = accept ? accept : "*/*";
    bool is_ipv6 = strchr(parsed.host, ':') != NULL;
    int format_rc =
        lantern_http_buffer_appendf(&request, "GET %s HTTP/1.1\r\nHost: ", parsed.path)
        || lantern_http_buffer_appendf(
               &request,
               is_ipv6 ? "[%s]:%u\r\n" : "%s:%u\r\n",
               parsed.host,
               (unsigned int)parsed.port)
        || lantern_http_buffer_appendf(
               &request,
               "Accept: %s\r\nConnection: close\r\n\r\n",
               accept_value);
    if (format_rc != 0)
    {
        lantern_http_buffer_free(&request);
        lantern_http_url_reset(&parsed);
        return LANTERN_HTTP_CLIENT_ERR;
    }

    int fd = connect_tcp(parsed.host, parsed.port);
    if (fd < 0)
    {
        lantern_http_buffer_free(&request);
        lantern_http_url_reset(&parsed);
        return LANTERN_HTTP_CLIENT_ERR;
    }

    int rc = LANTERN_HTTP_CLIENT_ERR;
    if (lantern_http_send_all(fd, request.data, request.len) == 0)
    {
        rc = read_response(fd, max_response_bytes, out_result);
    }

#if !defined(_WIN32)
    close(fd);
#endif
    lantern_http_buffer_free(&request);
    lantern_http_url_reset(&parsed);
    return rc;
}

void lantern_http_fetch_result_reset(struct lantern_http_fetch_result *result)
{
    if (!result)
    {
        return;
    }
    free(result->body);
    memset(result, 0, sizeof(*result));
}
