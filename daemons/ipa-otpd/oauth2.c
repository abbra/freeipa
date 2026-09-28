/*
 * FreeIPA 2FA companion daemon
 *
 * Authors: Sumit Bose <sbose@redhat.com>
 *
 * Copyright (C) 2021 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This file reaches out to a third-party IdP to handle an OAuth2
 * authentication request (stdio.c/query.c) if the user is configured
 * accordingly. The result is placed in the stdout queue (stdio.c).
 */

#include <krb5/krb5.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/random.h>
#include <signal.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <jansson.h>

#include "internal.h"
#include "ipa_hostname.h"

#define OIDC_CHILD_PATH "/usr/libexec/sssd/oidc_child"
#define ENV_AHDAPA_ISSUER_URL "ahdapa_issuer_url"

/* DARC (Device Authorization with Return Confirmation) in Ahdapa mode:
 * ipa-otpd on each KDC host is its own confidential client of the
 * integrated IdP, authenticated with private_key_jwt. The key pair is
 * created by the installer (ahdapainstance.py) and the public key is
 * registered for the client "ipa-otpd-<fqdn>". */
#define AHDAPA_OTPD_CLIENT_PREFIX "ipa-otpd-"
#define AHDAPA_OTPD_P12 "/var/lib/ipa/ipa-otpd/ahdapa-client.p12"
#define AHDAPA_OTPD_P12_PASSWORD "/var/lib/ipa/ipa-otpd/ahdapa-client.pwd"

/* Indicators added to the ticket through the KDC plugin. */
#define OAUTH2_IND_CONFIRMED "idp-confirmed"
#define OAUTH2_IND_MFA "idp-mfa"
#define OAUTH2_IND_PHR "idp-phr"

/* Per-principal initiation budget: at most OAUTH2_THROTTLE_BURST device
 * flows per OAUTH2_THROTTLE_WINDOW seconds, so that anyone able to start a
 * Kerberos login for a principal cannot flood the IdP (or the user) with
 * sign-in requests. Per-KDC-host limits are applied by the IdP, which sees
 * one client per host. */
#define OAUTH2_THROTTLE_BURST 5
#define OAUTH2_THROTTLE_WINDOW 300
#define OAUTH2_THROTTLE_SLOTS 256

struct child_ctx {
    int read_from_child;
    int write_to_child;
    verto_ev *read_ev;
    verto_ev *write_ev;
    verto_ev *child_ev;
    struct otpd_queue_item *item;
    struct otpd_queue_item *saved_item;
    enum oauth2_state oauth2_state;
    krb5_boolean use_ahdapa;
    /* Ahdapa mode: what oidc_child reads on stdin (PKCS#12 password, and
     * for the token request the state JSON with the confirmation code). */
    char *stdin_data;
    /* Ahdapa mode: the canonical principal uid@REALM, which Ahdapa returns
     * as sub and which the request is locked to (login_hint). */
    char *principal;
    /* A DARC confirmation code was sent with the token request. */
    krb5_boolean confirmed;
};

static void child_ctx_free(struct child_ctx *child_ctx)
{
    if (child_ctx == NULL) {
        return;
    }

    if (child_ctx->stdin_data != NULL) {
        explicit_bzero(child_ctx->stdin_data, strlen(child_ctx->stdin_data));
        free(child_ctx->stdin_data);
    }
    free(child_ctx->principal);
    free(child_ctx);
}

/* ── Ahdapa mode helpers ─────────────────────────────────────────────────── */

/* uid@REALM from the user entry, independent of how the client spelled the
 * principal (aliases, enterprise names). */
static char *canonical_principal(struct otpd_queue_item *item)
{
    char *realm = NULL;
    char *princ = NULL;

    if (item->user.uid == NULL
            || krb5_get_default_realm(ctx.kctx, &realm) != 0) {
        return NULL;
    }

    if (asprintf(&princ, "%s@%s", item->user.uid, realm) < 0) {
        princ = NULL;
    }
    krb5_free_default_realm(ctx.kctx, realm);

    return princ;
}

static char *read_secret_file(const char *path)
{
    char buf[1024];
    ssize_t len;
    int fd;
    char *out;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return NULL;
    }

    len = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (len <= 0) {
        explicit_bzero(buf, sizeof(buf));
        return NULL;
    }

    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        len--;
    }
    buf[len] = '\0';

    out = len > 0 ? strdup(buf) : NULL;
    explicit_bzero(buf, sizeof(buf));

    return out;
}

/* RFC 9396 detail the KDC host asserts about the request. Only values the
 * KDC observed belong here; the armor ticket client and address need MIT
 * krb5 kdcpreauth callbacks that do not exist yet (DARC phase 2). */
static char *krb5_tgt_details(const char *principal)
{
    const char *realm;
    json_t *jdetails;
    char *out;

    realm = strrchr(principal, '@');
    if (realm == NULL || realm[1] == '\0') {
        return NULL;
    }

    jdetails = json_pack("[{s:s, s:s, s:s, s:s}]",
                         "type", "krb5_tgt",
                         "realm", realm + 1,
                         "principal", principal,
                         "armor", "anonymous");
    if (jdetails == NULL) {
        return NULL;
    }

    out = json_dumps(jdetails, JSON_COMPACT | JSON_PRESERVE_ORDER);
    json_decref(jdetails);

    return out;
}

/* The confirmation code from User-Password (RADIUS pads it with NULs). */
static char *get_confirmation_code(krad_packet *req)
{
    const krb5_data *pwd;
    size_t len;

    pwd = krad_packet_get_attr(req, krad_attr_name2num("User-Password"), 0);
    if (pwd == NULL || pwd->data == NULL) {
        return NULL;
    }

    len = strnlen(pwd->data, pwd->length);
    if (len == 0) {
        return NULL;
    }

    return strndup(pwd->data, len);
}

/* The device code state (from Proxy-State) with the confirmation code
 * added, as one line of JSON for oidc_child. */
static char *state_with_code(const char *state, const char *code)
{
    json_error_t jerr;
    json_t *jstate;
    char *out;

    jstate = json_loads(state, 0, &jerr);
    if (!json_is_object(jstate)) {
        json_decref(jstate);
        return NULL;
    }

    if (code != NULL
            && json_object_set_new(jstate, "confirmation_code",
                                   json_string(code)) != 0) {
        json_decref(jstate);
        return NULL;
    }

    out = json_dumps(jstate, JSON_COMPACT | JSON_PRESERVE_ORDER);
    json_decref(jstate);

    return out;
}

static bool json_array_has(json_t *array, const char *value)
{
    json_t *jval;
    size_t i;

    json_array_foreach(array, i, jval) {
        if (json_is_string(jval) && strcmp(json_string_value(jval), value) == 0) {
            return true;
        }
    }

    return false;
}

/* Reply-Message for Access-Accept: indicators for the KDC plugin, from the
 * confirmation and from the strength of the upstream sign-in that the IdP
 * relays in acr/amr (RFC 8176 values). */
static char *accept_indicators(bool confirmed, const char *auth_context)
{
    json_error_t jerr;
    json_t *jctx = NULL;
    json_t *jamr = NULL;
    json_t *jind;
    json_t *jmsg;
    const char *acr = NULL;
    char *json_str;
    char *out = NULL;

    jind = json_array();
    if (jind == NULL) {
        return NULL;
    }

    if (confirmed) {
        json_array_append_new(jind, json_string(OAUTH2_IND_CONFIRMED));
    }

    if (auth_context != NULL) {
        jctx = json_loads(auth_context, 0, &jerr);
        if (json_is_object(jctx)) {
            jamr = json_object_get(jctx, "amr");
            acr = json_string_value(json_object_get(jctx, "acr"));
        }
    }

    if (json_is_array(jamr)
            && (json_array_has(jamr, "mfa") || json_array_has(jamr, "otp")
                || json_array_has(jamr, "hwk") || json_array_has(jamr, "sc"))) {
        json_array_append_new(jind, json_string(OAUTH2_IND_MFA));
    }
    if ((json_is_array(jamr) && json_array_has(jamr, "hwk"))
            || (acr != NULL && (strcmp(acr, "phr") == 0
                                || strcmp(acr, "phrh") == 0))) {
        json_array_append_new(jind, json_string(OAUTH2_IND_PHR));
    }

    if (json_array_size(jind) > 0) {
        /* "o" steals the array reference. */
        jmsg = json_pack("{s:i, s:o}", "v", 2, "indicators", jind);
        jind = NULL;
        json_str = jmsg != NULL
                    ? json_dumps(jmsg, JSON_COMPACT | JSON_PRESERVE_ORDER)
                    : NULL;
        if (json_str != NULL
                && asprintf(&out, "oauth2 %s", json_str) < 0) {
            out = NULL;
        }
        free(json_str);
        json_decref(jmsg);
    }

    json_decref(jind);
    json_decref(jctx);

    return out;
}

/* Per-principal throttling of device flow initiation. */
static bool oauth2_throttle(const char *principal)
{
    static struct {
        char *principal;
        time_t window_start;
        unsigned int count;
    } slots[OAUTH2_THROTTLE_SLOTS];
    time_t now = time(NULL);
    size_t oldest = 0;
    size_t i;

    for (i = 0; i < OAUTH2_THROTTLE_SLOTS; i++) {
        if (slots[i].principal != NULL
                && strcmp(slots[i].principal, principal) == 0) {
            if (now - slots[i].window_start >= OAUTH2_THROTTLE_WINDOW) {
                slots[i].window_start = now;
                slots[i].count = 0;
            }
            if (slots[i].count >= OAUTH2_THROTTLE_BURST) {
                return true;
            }
            slots[i].count++;
            return false;
        }
        if (slots[i].principal == NULL
                || slots[i].window_start < slots[oldest].window_start) {
            oldest = i;
            if (slots[i].principal == NULL) {
                break;
            }
        }
    }

    free(slots[oldest].principal);
    slots[oldest].principal = strdup(principal);
    slots[oldest].window_start = now;
    slots[oldest].count = 1;

    return false;
}

static int set_fd_nonblocking(int fd)
{
    int flags;
    int ret;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        ret = errno;
        return ret;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        ret = errno;
        return ret;
    }

    return 0;
}

static void free_child_ctx(verto_ctx *vctx, verto_ev *ev)
{
    (void)vctx; /* Unused */
    struct child_ctx *child_ctx;

    child_ctx = verto_get_private(ev);

    child_ctx_free(child_ctx);
}

static void oauth2_on_child_exit(verto_ctx *vctx, verto_ev *ev)
{
    (void)vctx; /* Unused */
    verto_proc_status st;

    st = verto_get_proc_status(ev);

    /* The krad req might not be available at this stage anymore, so
     * otpd_log_err() is used. */
    otpd_log_err(0, "Child finished with status [%d].", WEXITSTATUS(st));
}

static void oauth2_on_child_writable(verto_ctx *vctx, verto_ev *ev)
{
    (void)vctx; /* Unused */
    ssize_t io;
    struct child_ctx *child_ctx;
    struct iovec iov[3];

    child_ctx = verto_get_private(ev);
    if (child_ctx == NULL) {
        otpd_log_err(EINVAL, "Lost child context");
        verto_del(ev);
        return;
    }

    if (child_ctx->use_ahdapa) {
        /* Prepared in oauth2(): the PKCS#12 password, and for the token
         * request the state line with the confirmation code. */
        io = write(verto_get_fd(ev), child_ctx->stdin_data,
                   strlen(child_ctx->stdin_data));
    } else if (child_ctx->oauth2_state == OAUTH2_GET_DEVICE_CODE) {
        if (child_ctx->item->idp.ipaidpClientSecret != NULL) {
            io = write(verto_get_fd(ev), child_ctx->item->idp.ipaidpClientSecret,
                       strlen(child_ctx->item->idp.ipaidpClientSecret));
        } else {
            io = 0;
        }
    } else {
        int idx = 0;
        if (child_ctx->item->idp.ipaidpClientSecret != NULL) {
            iov[idx].iov_base = child_ctx->item->idp.ipaidpClientSecret;
            iov[idx].iov_len = strlen(child_ctx->item->idp.ipaidpClientSecret);
	    idx++;
            iov[idx].iov_base = "\n";
            iov[idx].iov_len = 1;
	    idx++;
        }
        iov[idx].iov_base = child_ctx->saved_item->oauth2.device_code_reply;
        iov[idx].iov_len = strlen(child_ctx->saved_item->oauth2.device_code_reply);
        idx++;
        io = writev(verto_get_fd(ev), iov, idx);
    }
    if (io < 0) {
        switch (errno) {
#if defined(EWOULDBLOCK) && (!defined(EAGAIN) || EAGAIN - EWOULDBLOCK != 0)
        case EWOULDBLOCK:
#endif
#if defined(EAGAIN)
        case EAGAIN:
#endif
        case ENOBUFS:
        case EINTR:
            /* In this case, we just need to try again. */
            return;
        default:
            /* Unrecoverable. */
            break;
        }
        otpd_log_err(errno, "Failed to send to child");
    }

    if (child_ctx->item->idp.ipaidpClientSecret != NULL) {
        explicit_bzero(child_ctx->item->idp.ipaidpClientSecret,
                       strlen(child_ctx->item->idp.ipaidpClientSecret));
    }
    if (child_ctx->stdin_data != NULL) {
        explicit_bzero(child_ctx->stdin_data, strlen(child_ctx->stdin_data));
    }
    if (child_ctx->saved_item != NULL) {
        otpd_queue_item_free(child_ctx->saved_item);
        child_ctx->saved_item = NULL;
    }
    verto_del(ev);
}

/* oidc_child will return two lines.
 * The first is a JSON formatted string containing the device code and other
 * data needed to get the access token in the second round. This will be
 * returned to the caller as Radius Proxy-State so that the caller will send
 * it back in the next round.
 * The second line is the string expected by the krb5 oauth2 pre-auth plugin
 * and will be send to the caller as Radius Reply-Message.
 */
static int handle_device_code_reply(struct child_ctx *child_ctx,
                                    const char *dc_reply, char *rad_reply)
{
    krad_attrset *attrset = NULL;
    int ret;
    krb5_data data = { 0 };
    struct otpd_queue_item *state_item = NULL;

    ret = otpd_queue_item_new(NULL, &state_item);
    if (ret != 0) {
        otpd_log_req(child_ctx->item->req, "Failed to allocate state item");
        goto done;
    }

    state_item->oauth2.device_code_reply = strdup(dc_reply);
    if (state_item->oauth2.device_code_reply == NULL) {
        ret = ENOMEM;
        otpd_log_req(child_ctx->item->req, "Failed to copy device code reply.");
        goto done;
    }

    ret = krad_attrset_new(ctx.kctx, &attrset);
    if (ret != 0) {
        otpd_log_req(child_ctx->item->req,
                     "Failed to create radius attribute set");
        goto done;
    }

    state_item->oauth2.state.magic = 0;

    state_item->oauth2.state.data = strdup(dc_reply);
    if (state_item->oauth2.state.data == NULL) {
        ret = ENOMEM;
        otpd_log_req(child_ctx->item->req,
                     "Failed to copy device code reply to krad.");
        goto done;
    }
    state_item->oauth2.state.length = strlen(dc_reply);

    ret = add_krad_attr_to_set(child_ctx->item->req,
                               attrset, &(state_item->oauth2.state),
                               krad_attr_name2num("Proxy-State"),
                               "Failed to serialize state to attribute set");
    if (ret != 0) {
        goto done;
    }

    data.magic = 0;
    data.data = rad_reply;
    data.length = strlen(rad_reply);
    ret = add_krad_attr_to_set(child_ctx->item->req, attrset, &data,
                               krad_attr_name2num("Reply-Message"),
                               "Failed to serialize reply to attribute set");
    if (ret != 0) {
        goto done;
    }

    ret = krad_packet_new_response(ctx.kctx, SECRET,
                                   krad_code_name2num("Access-Challenge"),
                                   attrset,
                                   child_ctx->item->req, &child_ctx->item->rsp);
    if (ret != 0) {
        otpd_log_err(ret, "Failed to create radius response");
        child_ctx->item->rsp = NULL;
    }

    otpd_queue_push(&ctx.oauth2_state.states, state_item);

    ret = 0;
done:
    krad_attrset_free(attrset);
    if (ret != 0) {
        if (state_item != NULL) {
            free(state_item->oauth2.state.data);
            free(state_item->oauth2.device_code_reply);
            free(state_item);
        }
    }

    return ret;
}

static int check_access_token_reply(struct child_ctx *child_ctx,
                                    char *buf, size_t len)
{
    int ret;
    const char *expected;
    size_t expected_len;
    const char *auth_context = NULL;
    char *indicators = NULL;
    krad_attrset *attrset = NULL;
    krb5_data data = { 0 };
    char *nl;

    if (child_ctx->use_ahdapa) {
        /* oidc_child --auth-context prints the ID token's acr/amr/auth_time
         * on the first line and the subject on the second. Ahdapa returns
         * uid@REALM as sub: compare with the canonical principal the
         * request was locked to. */
        nl = memchr(buf, '\n', len);
        if (nl != NULL) {
            *nl = '\0';
            auth_context = buf;
            len -= (nl + 1) - buf;
            buf = nl + 1;
        }
        if (child_ctx->principal == NULL) {
            return EPERM;
        }
        expected = child_ctx->principal;
        expected_len = strlen(expected);
    } else {
        if (child_ctx->item->user.ipaidpSub == NULL) {
            otpd_log_req(child_ctx->item->req,
                         "Missing ipaidpSub for access token verification");
            return EPERM;
        }
        expected = child_ctx->item->user.ipaidpSub;
        expected_len = strlen(expected);
    }

    if (expected_len != len || memcmp(expected, buf, len) != 0) {
        return EPERM;
    }

    /* Ahdapa mode: tell the KDC which indicators the ticket gets. */
    if (child_ctx->use_ahdapa) {
        indicators = accept_indicators(child_ctx->confirmed, auth_context);
        if (indicators != NULL) {
            ret = krad_attrset_new(ctx.kctx, &attrset);
            if (ret != 0) {
                free(indicators);
                return ret;
            }
            data.data = indicators;
            data.length = strlen(indicators);
            ret = add_krad_attr_to_set(child_ctx->item->req, attrset, &data,
                                       krad_attr_name2num("Reply-Message"),
                                       "Failed to serialize indicators");
            if (ret != 0) {
                krad_attrset_free(attrset);
                free(indicators);
                return ret;
            }
            otpd_log_req(child_ctx->item->req, "Access-Accept: %s",
                         indicators);
        }
    }

    ret = krad_packet_new_response(ctx.kctx, SECRET,
                                   krad_code_name2num("Access-Accept"), attrset,
                                   child_ctx->item->req, &child_ctx->item->rsp);
    if (ret != 0) {
        otpd_log_err(ret, "Failed to create radius response");
        child_ctx->item->rsp = NULL;
    }

    krad_attrset_free(attrset);
    free(indicators);

    return ret;
}

static void oauth2_on_child_readable(verto_ctx *vctx, verto_ev *ev)
{
    static char buf[10240];
    ssize_t io = 0;
    struct child_ctx *child_ctx = NULL;
    int ret;
    char *rad_reply;
    char *end;

    (void) vctx; /* Unused */

    child_ctx = (struct child_ctx *) verto_get_private(ev);
    if (child_ctx == NULL) {
        otpd_log_err(EINVAL, "Lost child context");
        verto_del(ev);
        return;
    }
    /* Make sure ctx.stdio.responses will at least return an error */
    child_ctx->item->rsp = NULL;
    child_ctx->item->sent = 0;

    io = read(verto_get_fd(ev), buf, sizeof(buf) - 1);
    if (io < 0) {
        otpd_log_err(errno, "Failed to read from child");
        goto done;
    }

    if (io == 0) {
        otpd_log_req(child_ctx->item->req,
                     "oidc_child closed stdout without producing output");
        verto_del(ev);
        goto done;
    }

    buf[io] = '\0';
    otpd_log_req(child_ctx->item->req, "Received: [%zu bytes]", (size_t)io);

    verto_del(ev);

    if (child_ctx->oauth2_state == OAUTH2_GET_DEVICE_CODE) {
        /* expect 2 lines of output. First the orginal JSON string return by
         * the IdP from the devicecode request which will be used as input to
         * the child process in the second run. Second the JSON string returned
         * in the radius reply. */

        rad_reply = memchr(buf, '\n', io);
        if (rad_reply != NULL) {
            *rad_reply = '\0';
            rad_reply++;
            end = memchr(rad_reply, '\n', io - (rad_reply - buf));
            if (end == NULL) {
                otpd_log_req(child_ctx->item->req, "Missing second new-line.");
                goto done;
            }
            *end = '\0';

            ret = handle_device_code_reply(child_ctx, buf, rad_reply);
            if (ret != 0) {
                otpd_log_req(child_ctx->item->req,
                             "Failed to handle device code reply.");
            }
        }
    } else if (child_ctx->oauth2_state == OAUTH2_GET_ACCESS_TOKEN) {
        ret = check_access_token_reply(child_ctx, buf, (size_t) io);
        if (ret != 0) {
                otpd_log_req(child_ctx->item->req,
                             "Failed to check access token reply.");
        }
    } else {
        /* error */
        otpd_log_req(child_ctx->item->req, "Unexpected state [%d].",
                                           child_ctx->oauth2_state);
    }

done:
    explicit_bzero(buf, sizeof(buf));
    otpd_queue_push(&ctx.stdio.responses, child_ctx->item);
    verto_set_flags(ctx.stdio.writer, VERTO_EV_FLAG_PERSIST |
                                      VERTO_EV_FLAG_IO_ERROR |
                                      VERTO_EV_FLAG_IO_READ |
                                      VERTO_EV_FLAG_IO_WRITE);
}

static const char *oauth2_state_to_str(enum oauth2_state oauth2_state)
{
    switch (oauth2_state) {
    case OAUTH2_NO:
        return "OAuth2 not available";
        break;
    case OAUTH2_GET_ISSUER:
        return "Get issuer from LDAP";
        break;
    case OAUTH2_GET_DEVICE_CODE:
        return "Get device code";
        break;
    case OAUTH2_GET_ACCESS_TOKEN:
        return "Get access token";
        break;
    default:
        return "Unknown OAuth2 state";
    }
}

int oauth2(struct otpd_queue_item **item, enum oauth2_state oauth2_state)
{
    int ret;
    pid_t child_pid;
    int pipefd_to_child[2] = { -1, -1};
    int pipefd_from_child[2] = { -1, -1};
    struct child_ctx *child_ctx;
    /* Up to 50 arguments to the helper supported. The amount of arguments
     * is controlled inside this function. Right now max used is below 20 */
    char *args[50] = {NULL};
    size_t args_idx = 0;
    krb5_data data_state = {0};
    struct otpd_queue_item *saved_item = NULL;
    char *ahdapa_client_id = NULL;
    char *details = NULL;
    char *password = NULL;
    char *code = NULL;
    char *state_line = NULL;

    if (oauth2_state != OAUTH2_GET_DEVICE_CODE
                && oauth2_state != OAUTH2_GET_ACCESS_TOKEN) {
        otpd_log_req((*item)->req, "Unexpected OAuth2 state [%d][%s]",
                     oauth2_state, oauth2_state_to_str(oauth2_state));
        return EINVAL;
    }

    if (oauth2_state == OAUTH2_GET_ACCESS_TOKEN) {
        ret = get_krad_attr_from_packet((*item)->req,
                                               krad_attr_name2num("Proxy-State"),
                                               &data_state);
        if ((ret != 0) || (data_state.length == 0)) {
            otpd_log_req((*item)->req, "Missing Radius Proxy-State attribute");
            return EINVAL;
        }

        saved_item = calloc(sizeof(struct otpd_queue_item), 1);
        if (saved_item == NULL) {
            otpd_log_req((*item)->req,
                         "Failed to allocate saved state item");
            krb5_free_data_contents(NULL, &data_state);
            return ENOMEM;
        }
        saved_item->oauth2.device_code_reply = strndup(data_state.data,
                                                       data_state.length);
        krb5_free_data_contents(NULL, &data_state);
        if (saved_item->oauth2.device_code_reply == NULL) {
            otpd_log_req((*item)->req, "Failed to copy device code reply");
            free(saved_item);
            saved_item = NULL;
            return ENOMEM;
        }
    }

    child_ctx = calloc(sizeof(struct child_ctx), 1);
    if (child_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }
    child_ctx->item = (*item);
    child_ctx->saved_item = saved_item;
    saved_item = NULL; /* ownership transferred to child_ctx */
    child_ctx->oauth2_state = oauth2_state;

    const char *ahdapa_issuer = getenv(ENV_AHDAPA_ISSUER_URL);
    child_ctx->use_ahdapa = (ahdapa_issuer != NULL && *ahdapa_issuer != '\0');

    if (child_ctx->use_ahdapa) {
        child_ctx->principal = canonical_principal(*item);
        if (child_ctx->principal == NULL) {
            ret = EINVAL;
            otpd_log_req((*item)->req, "Failed to build the user principal");
            goto done;
        }

        if (oauth2_state == OAUTH2_GET_DEVICE_CODE
                && oauth2_throttle(child_ctx->principal)) {
            ret = EACCES;
            otpd_log_req((*item)->req,
                         "Too many IdP sign-in requests for %s, rejecting",
                         child_ctx->principal);
            goto done;
        }

        password = read_secret_file(AHDAPA_OTPD_P12_PASSWORD);
        if (password == NULL) {
            ret = EIO;
            otpd_log_req((*item)->req, "Failed to read %s",
                         AHDAPA_OTPD_P12_PASSWORD);
            goto done;
        }

        if (oauth2_state == OAUTH2_GET_DEVICE_CODE) {
            /* The whole of stdin is the PKCS#12 password. */
            child_ctx->stdin_data = password;
            password = NULL;
        } else {
            /* First line: PKCS#12 password; second: the device code state
             * with the confirmation code the user typed (DARC), which the
             * KDC plugin put into User-Password. */
            code = get_confirmation_code((*item)->req);
            child_ctx->confirmed = (code != NULL);
            state_line = state_with_code(
                            child_ctx->saved_item->oauth2.device_code_reply,
                            code);
            if (state_line == NULL
                    || asprintf(&child_ctx->stdin_data, "%s\n%s\n",
                                password, state_line) < 0) {
                child_ctx->stdin_data = NULL;
                ret = ENOMEM;
                otpd_log_req((*item)->req, "Failed to prepare token request");
                goto done;
            }
        }
    }

    otpd_log_req((*item)->req, "oauth2 start: %s%s",
                               oauth2_state_to_str(oauth2_state),
                               child_ctx->use_ahdapa
                                   ? " (via Ahdapa)" : "");

    args[args_idx++] = OIDC_CHILD_PATH;

    if (oauth2_state == OAUTH2_GET_DEVICE_CODE) {
        args[args_idx++] = "--get-device-code";
    } else {
        args[args_idx++] = "--get-access-token";
    }

    if (child_ctx->use_ahdapa) {
        /* ahdapa_issuer_url is written to /etc/ipa/default.conf by
         * ahdapainstance.py and reaches ipa-otpd as an environment
         * variable via the systemd EnvironmentFile directive.
         *
         * In ahdapa mode oidc_child talks DARC to the local ahdapa
         * instance as this KDC host's confidential client
         * "ipa-otpd-<fqdn>" (private_key_jwt). Ahdapa owns the external
         * IdP registration and performs the federation itself; the device
         * grant is never used towards the external IdP. The client id
         * must match otpd_client_id() in ahdapainstance.py. */
        const char *fqdn = ipa_gethostfqdn();
        if (fqdn == NULL) {
            ret = EINVAL;
            otpd_log_req((*item)->req, "Failed to get host FQDN");
            goto done;
        }
        if (asprintf(&ahdapa_client_id, "%s%s",
                     AHDAPA_OTPD_CLIENT_PREFIX, fqdn) < 0) {
            ahdapa_client_id = NULL;
            ret = ENOMEM;
            otpd_log_err(ret, "Failed to allocate ahdapa client id");
            goto done;
        }

        args[args_idx++] = "--issuer-url";
        args[args_idx++] = (char *) ahdapa_issuer;

        args[args_idx++] = "--client-id";
        args[args_idx++] = ahdapa_client_id;

        args[args_idx++] = "--client-auth-method";
        args[args_idx++] = "jwt";

        args[args_idx++] = "--pkcs12-client-creds";
        args[args_idx++] = AHDAPA_OTPD_P12;

        args[args_idx++] = "--client-secret-stdin";

        args[args_idx++] = "--scope";
        args[args_idx++] = "openid";

        if (oauth2_state == OAUTH2_GET_DEVICE_CODE) {
            /* DARC: the terminal accepts an alphanumeric code; only this
             * user may approve (hint lock); the KDC asserts what is
             * requested. */
            details = krb5_tgt_details(child_ctx->principal);
            if (details == NULL) {
                ret = ENOMEM;
                otpd_log_req((*item)->req, "Failed to build krb5_tgt details");
                goto done;
            }

            args[args_idx++] = "--confirmation-input";
            args[args_idx++] = "alphanumeric";

            args[args_idx++] = "--login-hint";
            args[args_idx++] = child_ctx->principal;

            args[args_idx++] = "--authorization-details";
            args[args_idx++] = details;
        } else {
            args[args_idx++] = "--auth-context";
        }
    } else {
        if ((*item)->idp.ipaidpIssuerURL != NULL) {
            args[args_idx++] = "--issuer-url";
            args[args_idx++] = (*item)->idp.ipaidpIssuerURL;
        } else {
            args[args_idx++] = "--device-auth-endpoint";
            args[args_idx++] = (*item)->idp.ipaidpDevAuthEndpoint;

            args[args_idx++] = "--token-endpoint";
            args[args_idx++] = (*item)->idp.ipaidpTokenEndpoint;

            args[args_idx++] = "--userinfo-endpoint";
            args[args_idx++] = (*item)->idp.ipaidpUserInfoEndpoint;

            if ((*item)->idp.ipaidpKeysEndpoint) {
                args[args_idx++] = "--jwks-uri";
                args[args_idx++] = (*item)->idp.ipaidpKeysEndpoint;
            }
        }

        args[args_idx++] = "--client-id";
        args[args_idx++] = (*item)->idp.ipaidpClientID;

        if ((*item)->idp.ipaidpClientSecret) {
            args[args_idx++] = "--client-secret-stdin";
        }

        if ((*item)->idp.ipaidpScope) {
            args[args_idx++] = "--scope";
            args[args_idx++] = (*item)->idp.ipaidpScope;
        }

        if ((*item)->idp.ipaidpSub) {
            args[args_idx++] = "--user-identifier-attribute";
            args[args_idx++] = (*item)->idp.ipaidpSub;
        }
    }

    if ((*item)->idp.ipaidpDebugLevelStr != NULL) {
        args[args_idx++] = "--debug-level";
        args[args_idx++] = (*item)->idp.ipaidpDebugLevelStr;
    }

    if ((*item)->idp.ipaidpDebugCurl) {
        args[args_idx++] = "--libcurl-debug";
    }

#if 0
    for (int i = 0; args[i]; i++) {
        otpd_log_req((*item)->req, "oidc_child exec: %s", args[i]);
    }
#endif

    ret = pipe(pipefd_from_child);
    if (ret == -1) {
        ret = errno;
        goto done;
    }
    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        ret = errno;
        goto done;
    }

    child_pid = fork();

    if (child_pid == 0) { /* child */
        close(pipefd_to_child[1]);
        ret = dup2(pipefd_to_child[0], STDIN_FILENO);
        if (ret == -1) {
            exit(EXIT_FAILURE);
        }

        close(pipefd_from_child[0]);
        ret = dup2(pipefd_from_child[1], STDOUT_FILENO);
        if (ret == -1) {
            exit(EXIT_FAILURE);
        }

        execv(OIDC_CHILD_PATH, args);
        exit(EXIT_FAILURE);
    } else if (child_pid > 0) { /* parent */
        close(pipefd_to_child[0]);
        pipefd_to_child[0] = -1;
        ret = set_fd_nonblocking(pipefd_to_child[1]);
        if (ret != 0) {
            otpd_log_err(ret, "Failed to set write pipe non-blocking");
            goto done;
        }
        child_ctx->write_to_child = pipefd_to_child[1];

        close(pipefd_from_child[1]);
        pipefd_from_child[1] = -1;
        ret = set_fd_nonblocking(pipefd_from_child[0]);
        if (ret != 0) {
            otpd_log_err(ret, "Failed to set read pipe non-blocking");
            goto done;
        }
        child_ctx->read_from_child = pipefd_from_child[0];

        child_ctx->write_ev = verto_add_io(ctx.vctx, VERTO_EV_FLAG_PERSIST |
                                                     VERTO_EV_FLAG_IO_CLOSE_FD |
                                                     VERTO_EV_FLAG_IO_ERROR |
                                                     VERTO_EV_FLAG_IO_WRITE,
                                                     oauth2_on_child_writable,
                                                     child_ctx->write_to_child);
        if (child_ctx->write_ev == NULL) {
            ret = ENOMEM;
            otpd_log_err(ret, "Unable to initialize oauth2 writer event");
            goto done;
        }
        /* verto owns the fd now (IO_CLOSE_FD) */
        pipefd_to_child[1] = -1;
        verto_set_private(child_ctx->write_ev, child_ctx, NULL);

        child_ctx->read_ev = verto_add_io(ctx.vctx, VERTO_EV_FLAG_PERSIST |
                                                    VERTO_EV_FLAG_IO_CLOSE_FD |
                                                    VERTO_EV_FLAG_IO_ERROR |
                                                    VERTO_EV_FLAG_IO_READ,
                                                    oauth2_on_child_readable,
                                                    child_ctx->read_from_child);
        if (child_ctx->read_ev == NULL) {
            ret = ENOMEM;
            otpd_log_err(ret, "Unable to initialize oauth2 reader event");
            verto_del(child_ctx->write_ev);
            child_ctx->write_ev = NULL;
            goto done;
        }
        /* verto owns the fd now (IO_CLOSE_FD) */
        pipefd_from_child[0] = -1;
        verto_set_private(child_ctx->read_ev, child_ctx, NULL);

        child_ctx->child_ev = verto_add_child(ctx.vctx, VERTO_EV_FLAG_NONE,
                                              oauth2_on_child_exit, child_pid);
        if (child_ctx->child_ev == NULL) {
            ret = ENOMEM;
            otpd_log_err(ret, "Unable to initialize oauth2 child event");
            /* write_ev and read_ev own the fds (IO_CLOSE_FD), verto_del
             * closes them; child_ctx is freed below in done: */
            verto_del(child_ctx->read_ev);
            verto_del(child_ctx->write_ev);
            kill(child_pid, SIGKILL);
            waitpid(child_pid, NULL, 0);
            goto done;
        }
        verto_set_private(child_ctx->child_ev, child_ctx, free_child_ctx);
        /* child_ctx is now owned by verto via free_child_ctx */
        child_ctx = NULL;

    } else { /* error */
        ret = errno;
        otpd_log_err(ret, "Failed to fork oidc_child");
        goto done;
    }

    ret = 0;
done:
    free(ahdapa_client_id);
    free(details);
    if (password != NULL) {
        explicit_bzero(password, strlen(password));
        free(password);
    }
    if (code != NULL) {
        explicit_bzero(code, strlen(code));
        free(code);
    }
    if (state_line != NULL) {
        explicit_bzero(state_line, strlen(state_line));
        free(state_line);
    }
    if (ret == 0) {
        *item = NULL;
    } else {
        if (saved_item != NULL) {
            free(saved_item->oauth2.device_code_reply);
            free(saved_item);
        }
        if (pipefd_to_child[0] >= 0) close(pipefd_to_child[0]);
        if (pipefd_to_child[1] >= 0) close(pipefd_to_child[1]);
        if (pipefd_from_child[0] >= 0) close(pipefd_from_child[0]);
        if (pipefd_from_child[1] >= 0) close(pipefd_from_child[1]);
        child_ctx_free(child_ctx);
    }

    return ret;
}
