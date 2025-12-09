/**
 * @file client.c
 * @brief Lantern client core initialization and lifecycle management
 *
 * Implements the main client structure initialization, startup sequence,
 * and graceful shutdown. This is the central coordinator that brings together:
 * - Genesis configuration loading
 * - Consensus state management
 * - Networking (libp2p, gossipsub, request/response)
 * - Validator services
 * - HTTP and metrics servers
 *
 * @see client_internal.h for shared internal declarations
 */

#include "lantern/core/client.h"
#include "client_internal.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/time.h>
#endif

#include "internal/yaml_parser.h"
#include "libp2p/errors.h"
#include "libp2p/events.h"
#include "libp2p/host.h"
#include "libp2p/protocol_dial.h"
#include "libp2p/stream.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id/peer_id.h"
#include "protocol/gossipsub/gossipsub.h"
#include "protocol/identify/protocol_identify.h"
#include "protocol/ping/protocol_ping.h"

#include "lantern/consensus/containers.h"
#include "lantern/consensus/duties.h"
#include "lantern/consensus/fork_choice.h"
#include "lantern/consensus/hash.h"
#include "lantern/consensus/runtime.h"
#include "lantern/consensus/signature.h"
#include "lantern/consensus/ssz.h"
#include "lantern/consensus/state.h"
#include "lantern/crypto/hash_sig.h"
#include "lantern/encoding/snappy.h"
#include "lantern/http/server.h"
#include "lantern/metrics/lean_metrics.h"
#include "lantern/networking/messages.h"
#include "lantern/networking/reqresp_service.h"
#include "lantern/storage/storage.h"
#include "lantern/support/log.h"
#include "lantern/support/secure_mem.h"
#include "lantern/support/strings.h"
#include "lantern/support/time.h"

/* ============================================================================
 * External Functions (from client_init.c)
 * ============================================================================ */

extern int copy_genesis_paths(struct lantern_genesis_paths *paths,
                              const struct lantern_client_options *options);
extern void reset_genesis_paths(struct lantern_genesis_paths *paths);
extern int append_genesis_bootnodes(struct lantern_client *client);
extern int compute_local_validator_assignment(struct lantern_client *client);
extern int populate_local_validators(struct lantern_client *client);
extern int init_consensus_runtime(struct lantern_client *client);


/**
 * @brief Initialize client options with default values.
 *
 * Sets all fields to their default values, including paths to configuration
 * files, network settings, and an empty bootnode list.
 *
 * @param options  Client options struct to initialize
 *
 * @note Thread safety: None required - operates on caller-provided struct.
 */
void lantern_client_options_init(struct lantern_client_options *options)
{
    if (!options)
    {
        return;
    }

    options->data_dir = LANTERN_DEFAULT_DATA_DIR;
    options->genesis_config_path = LANTERN_DEFAULT_GENESIS_CONFIG;
    options->validator_registry_path = LANTERN_DEFAULT_VALIDATOR_REGISTRY;
    options->nodes_path = LANTERN_DEFAULT_NODES_FILE;
    options->genesis_state_path = LANTERN_DEFAULT_GENESIS_STATE;
    options->validator_config_path = LANTERN_DEFAULT_VALIDATOR_CONFIG;
    options->node_id = LANTERN_DEFAULT_NODE_ID;
    options->node_key_hex = NULL;
    options->node_key_path = NULL;
    options->listen_address = LANTERN_DEFAULT_LISTEN_ADDR;
    options->http_port = LANTERN_DEFAULT_HTTP_PORT;
    options->metrics_port = LANTERN_DEFAULT_METRICS_PORT;
    options->devnet = LANTERN_DEFAULT_DEVNET;
    lantern_string_list_init(&options->bootnodes);
    options->hash_sig_key_dir = NULL;
    options->hash_sig_public_path = NULL;
    options->hash_sig_secret_path = NULL;
    options->hash_sig_public_template = NULL;
    options->hash_sig_secret_template = NULL;
}


/**
 * @brief Free resources allocated within client options.
 *
 * Releases the bootnode list and any other dynamically allocated resources.
 * The options struct itself is not freed (caller-owned).
 *
 * @param options  Client options struct to free (may be NULL)
 *
 * @note Thread safety: None required - operates on caller-provided struct.
 */
void lantern_client_options_free(struct lantern_client_options *options)
{
    if (!options)
    {
        return;
    }
    lantern_string_list_reset(&options->bootnodes);
}


/**
 * @brief Add a bootnode address to client options.
 *
 * Appends an ENR string to the list of bootnodes that will be used
 * during client initialization to discover peers.
 *
 * @param options   Client options struct to modify
 * @param bootnode  ENR string (e.g., "enr:-...")
 *
 * @return 0 on success
 * @return -1 if options or bootnode is NULL, or on allocation failure
 *
 * @note Thread safety: None required - operates on caller-provided struct.
 */
int lantern_client_options_add_bootnode(struct lantern_client_options *options, const char *bootnode)
{
    if (!options || !bootnode)
    {
        return -1;
    }
    return lantern_string_list_append(&options->bootnodes, bootnode);
}


/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

static void client_reset_base(struct lantern_client *client)
{
    memset(client, 0, sizeof(*client));
    lantern_string_list_init(&client->bootnodes);
    lantern_string_list_init(&client->dialer_peers);
    lantern_string_list_init(&client->connected_peer_ids);
    lantern_string_list_init(&client->status_failure_peer_ids);
    lantern_genesis_artifacts_init(&client->genesis);
    lantern_enr_record_init(&client->local_enr);
    lantern_libp2p_host_init(&client->network);
    client->ping_server = NULL;
    client->ping_running = false;
    lantern_gossipsub_service_init(&client->gossip);
    lantern_reqresp_service_init(&client->reqresp);
    client->reqresp_running = false;
    lantern_validator_assignment_reset(&client->validator_assignment);
    client->has_validator_assignment = false;
    lantern_consensus_runtime_reset(&client->runtime);
    client->has_runtime = false;
    lantern_metrics_server_init(&client->metrics_server);
    client->metrics_running = false;
    lantern_http_server_init(&client->http_server);
    client->http_running = false;
    lantern_state_init(&client->state);
    lean_metrics_reset();
    client->state_lock_initialized = false;
    lantern_fork_choice_init(&client->fork_choice);
    client->has_fork_choice = false;
    client->dialer_thread_started = false;
    client->dialer_stop_flag = 1;
    client->ping_thread_started = false;
    client->ping_stop_flag = 1;
    pending_block_list_init(&client->pending_blocks);
    client->pending_lock_initialized = false;
}


static int client_apply_options(
    struct lantern_client *client,
    const struct lantern_client_options *options)
{
    if (set_owned_string(&client->data_dir, options->data_dir) != 0)
    {
        return -1;
    }
    if (set_owned_string(&client->node_id, options->node_id) != 0)
    {
        return -1;
    }
    lantern_log_set_node_id(client->node_id);
    if (set_owned_string(&client->listen_address, options->listen_address) != 0)
    {
        return -1;
    }
    if (set_owned_string(&client->devnet, options->devnet) != 0)
    {
        return -1;
    }

    const char *disable_guard_env = getenv("LANTERN_DEBUG_DISABLE_STATUS_GUARD");
    if (disable_guard_env
        && disable_guard_env[0] != '\0'
        && !(disable_guard_env[0] == '0' && disable_guard_env[1] == '\0'))
    {
        client->status_guard_disabled = true;
        lantern_log_warn(
            "reqresp",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "status guard disabled via LANTERN_DEBUG_DISABLE_STATUS_GUARD=\"%s\"",
            disable_guard_env);
    }

    client->http_port = options->http_port;
    client->metrics_port = options->metrics_port;
    return 0;
}


static int client_init_locks(struct lantern_client *client)
{
    if (pthread_mutex_init(&client->pending_lock, NULL) != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to initialize pending block lock");
        return -1;
    }
    client->pending_lock_initialized = true;

    if (!client->status_lock_initialized)
    {
        if (pthread_mutex_init(&client->status_lock, NULL) != 0)
        {
            lantern_log_error(
                "client",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to initialize peer status lock");
            return -1;
        }
        client->status_lock_initialized = true;
    }

    if (!client->state_lock_initialized)
    {
        if (pthread_mutex_init(&client->state_lock, NULL) != 0)
        {
            lantern_log_error(
                "client",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to initialize state lock");
            return -1;
        }
        client->state_lock_initialized = true;
    }

    if (!client->peer_vote_lock_initialized)
    {
        if (pthread_mutex_init(&client->peer_vote_lock, NULL) != 0)
        {
            lantern_log_error(
                "client",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to initialize vote metrics lock");
            return -1;
        }
        client->peer_vote_lock_initialized = true;
    }

    return 0;
}


static int client_prepare_storage_and_genesis(
    struct lantern_client *client,
    const struct lantern_client_options *options)
{
    if (lantern_storage_prepare(client->data_dir) != 0)
    {
        lantern_log_error(
            "storage",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to prepare data directory '%s'",
            client->data_dir);
        return -1;
    }

    if (lantern_string_list_copy(&client->bootnodes, &options->bootnodes) != 0)
    {
        return -1;
    }

    if (copy_genesis_paths(&client->genesis_paths, options) != 0)
    {
        return -1;
    }

    if (lantern_genesis_load(&client->genesis, &client->genesis_paths) != 0)
    {
        return -1;
    }

    if (lantern_validator_config_assign_ranges(
            &client->genesis.validator_config,
            client->genesis.chain_config.validator_count)
        != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "validator-config does not cover %" PRIu64 " validators",
            client->genesis.chain_config.validator_count);
        return -1;
    }

    if (lantern_validator_config_apply_assignments(
            &client->genesis.validator_config,
            client->genesis_paths.validator_registry_path,
            client->genesis.chain_config.validator_count)
        != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "validator assignment mapping invalid or incomplete");
        return -1;
    }

    return 0;
}


static bool client_try_genesis_from_pubkeys(struct lantern_client *client)
{
    if (!client->genesis.chain_config.validator_pubkeys
        || client->genesis.chain_config.validator_pubkeys_count == 0)
    {
        return false;
    }

    size_t vcount = client->genesis.chain_config.validator_pubkeys_count;
    if (lantern_state_generate_genesis(
            &client->state, client->genesis.chain_config.genesis_time, vcount)
        != 0)
    {
        return false;
    }

    if (lantern_state_set_validator_pubkeys(
            &client->state,
            client->genesis.chain_config.validator_pubkeys,
            vcount)
        != 0)
    {
        return false;
    }

    client->genesis_fallback_used = false;
    return true;
}


static bool client_try_genesis_from_ssz(struct lantern_client *client)
{
    if (!client->genesis.state_bytes || client->genesis.state_size == 0)
    {
        return false;
    }

    if (lantern_ssz_decode_state(
            &client->state,
            client->genesis.state_bytes,
            client->genesis.state_size)
        != 0)
    {
        return false;
    }

    client->genesis_fallback_used = false;
    return true;
}


static bool client_try_genesis_from_registry(struct lantern_client *client)
{
    size_t vcount = client->genesis.validator_registry.count;
    if (vcount == 0
        || vcount != client->genesis.chain_config.validator_count)
    {
        lantern_log_warn(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "validator registry count (%zu) does not match chain config (%" PRIu64 ")",
            vcount,
            client->genesis.chain_config.validator_count);
        return false;
    }

    if (lantern_state_generate_genesis(
            &client->state,
            client->genesis.chain_config.genesis_time,
            vcount)
        != 0)
    {
        return false;
    }

    uint8_t *pubkeys = calloc(vcount, LANTERN_VALIDATOR_PUBKEY_SIZE);
    if (!pubkeys)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to allocate validator pubkey buffer");
        return false;
    }

    bool pubkey_ok = true;
    for (size_t i = 0; i < vcount; ++i)
    {
        const struct lantern_validator_record *rec = &client->genesis.validator_registry.records[i];
        uint8_t *dest = pubkeys + (i * LANTERN_VALIDATOR_PUBKEY_SIZE);
        if (rec->has_pubkey_bytes)
        {
            memcpy(dest, rec->pubkey_bytes, LANTERN_VALIDATOR_PUBKEY_SIZE);
        }
        else if (rec->pubkey_hex
                 && lantern_hex_decode(rec->pubkey_hex, dest, LANTERN_VALIDATOR_PUBKEY_SIZE) == 0)
        {
            /* decoded */
        }
        else
        {
            lantern_log_error(
                "client",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "missing or invalid pubkey for validator index=%zu; aborting genesis build",
                i);
            pubkey_ok = false;
            break;
        }
    }

    bool success = false;
    if (pubkey_ok
        && lantern_state_set_validator_pubkeys(&client->state, pubkeys, vcount) == 0)
    {
        client->genesis_fallback_used = true;
        success = true;
    }

    free(pubkeys);
    return success;
}


static void client_log_generated_anchor_block(struct lantern_client *client)
{
    LanternState generated_state;
    lantern_state_init(&generated_state);
    if (lantern_state_generate_genesis(
            &generated_state,
            client->state.config.genesis_time,
            client->state.config.num_validators)
        != 0)
    {
        return;
    }

    LanternRoot generated_state_root;
    if (lantern_hash_tree_root_state(&generated_state, &generated_state_root) != 0)
    {
        return;
    }

    LanternBlock generated_block;
    memset(&generated_block, 0, sizeof(generated_block));
    generated_block.slot = generated_state.slot;
    generated_block.proposer_index = 0;
    generated_block.parent_root = generated_state.latest_block_header.parent_root;
    generated_block.state_root = generated_state_root;
    lantern_block_body_init(&generated_block.body);

    LanternRoot generated_block_root;
    if (lantern_hash_tree_root_block(&generated_block, &generated_block_root) == 0)
    {
        char generated_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
        format_root_hex(&generated_block_root, generated_hex, sizeof(generated_hex));
        lantern_log_info(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "generated anchor block root=%s",
            generated_hex[0] ? generated_hex : "0x0");
    }
    lantern_block_body_reset(&generated_block.body);
}


static void client_log_genesis_anchors(struct lantern_client *client, const LanternRoot *state_root)
{
    LanternRoot header_root;
    LanternRoot genesis_block_root;
    LanternRoot genesis_signed_block_root;
    LanternRoot canonical_header_root;
    LanternRoot spec_header_root;
    char header_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    char state_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    char block_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    char signed_block_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    char parent_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    char canonical_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    char body_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    char spec_header_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    header_hex[0] = '\0';
    state_hex[0] = '\0';
    block_hex[0] = '\0';
    signed_block_hex[0] = '\0';
    parent_hex[0] = '\0';
    canonical_hex[0] = '\0';
    body_hex[0] = '\0';
    spec_header_hex[0] = '\0';
    if (lantern_hash_tree_root_block_header(&client->state.latest_block_header, &header_root) == 0)
    {
        format_root_hex(&header_root, header_hex, sizeof(header_hex));
    }
    if (state_root)
    {
        format_root_hex(state_root, state_hex, sizeof(state_hex));
    }
    LanternBlock genesis_block;
    memset(&genesis_block, 0, sizeof(genesis_block));
    genesis_block.slot = client->state.latest_block_header.slot;
    genesis_block.proposer_index = client->state.latest_block_header.proposer_index;
    genesis_block.parent_root = client->state.latest_block_header.parent_root;
    genesis_block.state_root = state_root ? *state_root : client->state.latest_block_header.state_root;
    lantern_block_body_init(&genesis_block.body);
    if (lantern_hash_tree_root_block(&genesis_block, &genesis_block_root) == 0)
    {
        format_root_hex(&genesis_block_root, block_hex, sizeof(block_hex));
    }
    lantern_block_body_reset(&genesis_block.body);
    format_root_hex(
        &client->state.latest_block_header.parent_root,
        parent_hex,
        sizeof(parent_hex));
    LanternBlockHeader canonical_header = client->state.latest_block_header;
    canonical_header.state_root = state_root ? *state_root : canonical_header.state_root;
    if (lantern_hash_tree_root_block_header(&canonical_header, &canonical_header_root) == 0)
    {
        format_root_hex(&canonical_header_root, canonical_hex, sizeof(canonical_hex));
    }
    LanternBlockBody empty_body_snapshot;
    lantern_block_body_init(&empty_body_snapshot);
    LanternRoot default_body_root;
    if (lantern_hash_tree_root_block_body(&empty_body_snapshot, &default_body_root) != 0)
    {
        memset(&default_body_root, 0, sizeof(default_body_root));
    }
    lantern_block_body_reset(&empty_body_snapshot);
    LanternBlockHeader spec_header = client->state.latest_block_header;
    spec_header.state_root = state_root ? *state_root : spec_header.state_root;
    spec_header.body_root = default_body_root;
    if (lantern_hash_tree_root_block_header(&spec_header, &spec_header_root) == 0)
    {
        format_root_hex(&spec_header_root, spec_header_hex, sizeof(spec_header_hex));
    }
    format_root_hex(
        &client->state.latest_block_header.body_root,
        body_hex,
        sizeof(body_hex));
    LanternSignedBlock genesis_signed;
    lantern_signed_block_with_attestation_init(&genesis_signed);
    genesis_signed.message.block = genesis_block;
    (void)lantern_block_signatures_resize(&genesis_signed.signatures, 0);
    if (lantern_hash_tree_root_signed_block(&genesis_signed, &genesis_signed_block_root) == 0)
    {
        format_root_hex(&genesis_signed_block_root, signed_block_hex, sizeof(signed_block_hex));
    }

    client_log_generated_anchor_block(client);

    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "genesis anchors header_root=%s state_root=%s body_root=%s block_root=%s signed_block_root=%s canonical_header_root=%s spec_header_root=%s parent_root=%s",
        header_hex[0] ? header_hex : "0x0",
        state_hex[0] ? state_hex : "0x0",
        body_hex[0] ? body_hex : "0x0",
        block_hex[0] ? block_hex : "0x0",
        signed_block_hex[0] ? signed_block_hex : "0x0",
        canonical_hex[0] ? canonical_hex : "0x0",
        spec_header_hex[0] ? spec_header_hex : "0x0",
        parent_hex[0] ? parent_hex : "0x0");
}


static int client_finalize_genesis_state(struct lantern_client *client)
{
    if (lantern_state_prepare_validator_votes(
            &client->state,
            client->state.config.num_validators)
        != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to prepare validator vote records");
        return -1;
    }
    LanternRoot state_root;
    if (lantern_hash_tree_root_state(&client->state, &state_root) != 0)
    {
        return -1;
    }

    client_log_genesis_anchors(client, &state_root);
    client->has_state = true;
    return 0;
}


static int client_generate_state_from_genesis(struct lantern_client *client)
{
    if (client_try_genesis_from_pubkeys(client))
    {
        return client_finalize_genesis_state(client);
    }

    if (client_try_genesis_from_ssz(client))
    {
        return client_finalize_genesis_state(client);
    }

    if (client_try_genesis_from_registry(client))
    {
        return client_finalize_genesis_state(client);
    }

    return -1;
}


static int client_load_or_build_state(struct lantern_client *client, bool *loaded_from_storage)
{
    bool from_storage = false;
    int storage_state_rc = lantern_storage_load_state(client->data_dir, &client->state);
    if (storage_state_rc == 0)
    {
        client->has_state = true;
        from_storage = true;
    }
    else if (storage_state_rc < 0)
    {
        lantern_log_error(
            "storage",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to load persisted state");
        return -1;
    }
    else
    {
        if (client_generate_state_from_genesis(client) != 0)
        {
            return -1;
        }
    }

    if (client->has_state)
    {
        int votes_rc = lantern_storage_load_votes(client->data_dir, &client->state);
        if (votes_rc < 0)
        {
            lantern_log_error(
                "storage",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to load persisted votes");
            return -1;
        }
        if (initialize_fork_choice(client) != 0)
        {
            return -1;
        }
        if (restore_persisted_blocks(client) != 0)
        {
            return -1;
        }
    }

    if (client->has_state && !from_storage)
    {
        if (lantern_storage_save_state(client->data_dir, &client->state) != 0)
        {
            lantern_log_warn(
                "storage",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to persist initial state snapshot");
        }
        if (lantern_storage_save_votes(client->data_dir, &client->state) != 0)
        {
            lantern_log_warn(
                "storage",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to persist initial votes snapshot");
        }
    }

    if (loaded_from_storage)
    {
        *loaded_from_storage = from_storage;
    }
    return client->has_state ? 0 : -1;
}


static int client_setup_validators(
    struct lantern_client *client,
    const struct lantern_client_options *options)
{
    client->assigned_validators = lantern_validator_config_find(
        &client->genesis.validator_config,
        client->node_id);

    if (!client->assigned_validators)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "node-id '%s' not found in validator-config",
            client->node_id);
        return -1;
    }

    if (!client->assigned_validators->enr.ip || client->assigned_validators->enr.quic_port == 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "validator '%s' missing ENR fields",
            client->node_id);
        return -1;
    }

    if (configure_hash_sig_sources(client, options) != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to configure hash-sig key sources");
        return -1;
    }

    adopt_validator_listen_address(client);

    if (compute_local_validator_assignment(client) != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to compute validator assignment for '%s'",
            client->node_id);
        return -1;
    }

    if (populate_local_validators(client) != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to enumerate local validators for '%s'",
            client->node_id);
        return -1;
    }

    if (client->local_validator_count == 0 || !client->has_state)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "no local validators assigned for '%s'; check validator-config",
            client->node_id);
        return -1;
    }

    if (lantern_client_refresh_state_validators(client) != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to refresh validator pubkeys for '%s'",
            client->node_id);
        return -1;
    }

    if (load_hash_sig_keys(client) != 0)
    {
        return -1;
    }

    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "validator slice start=%" PRIu64 " count=%" PRIu64,
        client->validator_assignment.start_index,
        client->validator_assignment.count);

    return 0;
}


static int client_start_runtime(struct lantern_client *client)
{
    if (init_consensus_runtime(client) != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to initialize consensus runtime");
        return -1;
    }

    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "consensus runtime ready genesis_time=%" PRIu64 " validators=%" PRIu64,
        client->genesis.chain_config.genesis_time,
        client->genesis.chain_config.validator_count);
    return 0;
}


static int client_start_network(
    struct lantern_client *client,
    const struct lantern_client_options *options,
    uint8_t node_key[32])
{
    if (load_node_key_bytes(options, node_key) != 0)
    {
        return -1;
    }
    memcpy(client->node_private_key, node_key, 32);
    client->has_node_private_key = true;

    struct lantern_libp2p_config net_cfg = {
        .listen_multiaddr = client->listen_address,
        .secp256k1_secret = node_key,
        .secret_len = 32,
        .allow_outbound_identify = 1,
    };

    if (lantern_libp2p_host_start(&client->network, &net_cfg) != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to initialize libp2p host");
        return -1;
    }

    if (!client->connection_lock_initialized)
    {
        if (pthread_mutex_init(&client->connection_lock, NULL) != 0)
        {
            lantern_log_error(
                "network",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to initialize connection lock");
            return -1;
        }
        client->connection_lock_initialized = true;
    }
    connection_counter_reset(client);

    if (libp2p_event_subscribe(
            client->network.host,
            connection_events_cb,
            client,
            &client->connection_subscription)
        != 0)
    {
        lantern_log_error(
            "network",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to subscribe to libp2p connection events");
        return -1;
    }

    libp2p_protocol_server_t *ping_server = NULL;
    if (libp2p_ping_service_start(client->network.host, &ping_server) != 0)
    {
        lantern_log_error(
            "network",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to start libp2p ping service");
        return -1;
    }

    client->ping_server = ping_server;
    client->ping_running = true;
    lantern_log_info(
        "network",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "libp2p ping service started");

    return 0;
}


static int client_start_protocols(struct lantern_client *client, uint8_t node_key[32])
{
    struct lantern_gossipsub_config gossip_cfg = {
        .host = client->network.host,
        .devnet = client->devnet,
    };
    lantern_gossipsub_service_set_block_handler(&client->gossip, gossip_block_handler, client);
    lantern_gossipsub_service_set_vote_handler(&client->gossip, gossip_vote_handler, client);
    if (lantern_gossipsub_service_start(&client->gossip, &gossip_cfg) != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to start gossipsub service");
        return -1;
    }
    client->gossip_running = true;

    struct lantern_reqresp_service_callbacks req_callbacks;
    memset(&req_callbacks, 0, sizeof(req_callbacks));
    req_callbacks.context = client;
    req_callbacks.build_status = reqresp_build_status;
    req_callbacks.handle_status = reqresp_handle_status;
    req_callbacks.status_failure = reqresp_status_failure;
    req_callbacks.collect_blocks = reqresp_collect_blocks;

    struct lantern_reqresp_service_config req_config;
    memset(&req_config, 0, sizeof(req_config));
    req_config.host = client->network.host;
    req_config.callbacks = &req_callbacks;
    if (lantern_reqresp_service_start(&client->reqresp, &req_config) != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to start request/response service");
        return -1;
    }
    client->reqresp_running = true;

    lantern_client_seed_reqresp_peer_modes(client);
    if (append_genesis_bootnodes(client) != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to append bootnodes from genesis");
        return -1;
    }

    if (lantern_enr_record_build_v4(
            &client->local_enr,
            node_key,
            client->assigned_validators->enr.ip,
            client->assigned_validators->enr.quic_port,
            client->assigned_validators->enr.sequence)
        != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to build local ENR");
        return -1;
    }

    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "local ENR prepared sequence=%" PRIu64,
        client->assigned_validators->enr.sequence);

    memset(node_key, 0, 32);
    return 0;
}


static void client_start_background_services(struct lantern_client *client)
{
    if (start_peer_dialer(client) != 0)
    {
        lantern_log_warn(
            "network",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to start peer dialer thread");
    }

    if (start_ping_service(client) != 0)
    {
        lantern_log_warn(
            "network",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to start ping service thread");
    }

    if (start_validator_service(client) != 0)
    {
        lantern_log_warn(
            "validator",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "validator duties inactive");
    }
}


static int client_start_apis(struct lantern_client *client)
{
    struct lantern_http_server_config http_config;
    memset(&http_config, 0, sizeof(http_config));
    http_config.port = client->http_port;
    http_config.callbacks.context = client;
    http_config.callbacks.snapshot_head = http_snapshot_head;
    http_config.callbacks.validator_count = http_validator_count_cb;
    http_config.callbacks.validator_info = http_validator_info_cb;
    http_config.callbacks.set_validator_status = http_set_validator_status_cb;
    if (lantern_http_server_start(&client->http_server, &http_config) != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to start HTTP server on port %" PRIu16,
            client->http_port);
        return -1;
    }
    client->http_running = true;

    struct lantern_metrics_callbacks metrics_callbacks;
    memset(&metrics_callbacks, 0, sizeof(metrics_callbacks));
    metrics_callbacks.context = client;
    metrics_callbacks.snapshot = metrics_snapshot_cb;
    if (client->metrics_port != 0)
    {
        if (lantern_metrics_server_start(
                &client->metrics_server,
                client->metrics_port,
                &metrics_callbacks)
            != 0)
        {
            lantern_log_error(
                "client",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to start metrics server on port %" PRIu16,
                client->metrics_port);
            return -1;
        }
        client->metrics_running = true;
    }

    return 0;
}


/**
 * @brief Initialize and start the Lantern client.
 *
 * Sets up all subsystems including networking, gossip, request/response,
 * validator services, and HTTP/metrics servers. This is the main entry
 * point for starting a Lantern node.
 *
 * Initialization order:
 * 1. Genesis and state loading
 * 2. Validator configuration
 * 3. Networking (libp2p host, gossipsub, request/response)
 * 4. Services (HTTP, metrics, validator duties)
 *
 * @param client   Client struct to initialize (must be zeroed or freshly allocated)
 * @param options  Configuration options (not modified, can be freed after call)
 *
 * @return 0 on success
 * @return -1 on initialization failure (client is cleaned up via lantern_shutdown)
 *
 * @note Thread safety: Must be called from a single thread before any
 *       concurrent access to the client. Initializes all internal locks.
 */
int lantern_init(struct lantern_client *client, const struct lantern_client_options *options)
{
    if (!client || !options)
    {
        return -1;
    }

    uint8_t node_key[32];

    client_reset_base(client);

    if (client_apply_options(client, options) != 0)
    {
        goto error;
    }

    if (client_init_locks(client) != 0)
    {
        goto error;
    }

    if (client_prepare_storage_and_genesis(client, options) != 0)
    {
        goto error;
    }

    if (client_load_or_build_state(client, NULL) != 0)
    {
        goto error;
    }

    if (client_setup_validators(client, options) != 0)
    {
        goto error;
    }

    if (client_start_runtime(client) != 0)
    {
        goto error;
    }

    if (client_start_network(client, options, node_key) != 0)
    {
        memset(node_key, 0, sizeof(node_key));
        goto error;
    }

    if (client_start_protocols(client, node_key) != 0)
    {
        memset(node_key, 0, sizeof(node_key));
        goto error;
    }

    client_start_background_services(client);

    if (client_start_apis(client) != 0)
    {
        goto error;
    }

    return 0;

error:
    memset(node_key, 0, sizeof(node_key));
    lantern_shutdown(client);
    return -1;
}


/**
 * @brief Shutdown and clean up the Lantern client.
 *
 * Stops all services and releases all resources. After this call, the client
 * struct is zeroed and must be re-initialized before reuse.
 *
 * Shutdown order (reverse of initialization):
 * 1. Validator and ping services
 * 2. HTTP and metrics servers
 * 3. Networking (gossipsub, request/response, libp2p)
 * 4. State and fork choice
 * 5. Genesis artifacts and configuration
 *
 * @param client  Client to shutdown (may be NULL, which is a no-op)
 *
 * @note Thread safety: Must be called from a single thread after all other
 *       threads have stopped using the client. Destroys all internal locks.
 */
void lantern_shutdown(struct lantern_client *client)
{
    if (!client)
    {
        return;
    }

    stop_validator_service(client);
    stop_ping_service(client);
    stop_peer_dialer(client);
    free_hash_sig_pubkeys(client);
    free(client->hash_sig_key_dir);
    client->hash_sig_key_dir = NULL;
    free(client->hash_sig_public_template);
    client->hash_sig_public_template = NULL;
    free(client->hash_sig_secret_template);
    client->hash_sig_secret_template = NULL;
    free(client->hash_sig_public_path);
    client->hash_sig_public_path = NULL;
    free(client->hash_sig_secret_path);
    client->hash_sig_secret_path = NULL;

    lantern_metrics_server_stop(&client->metrics_server);
    lantern_metrics_server_init(&client->metrics_server);
    client->metrics_running = false;

    lantern_http_server_stop(&client->http_server);
    lantern_http_server_init(&client->http_server);
    client->http_running = false;

    if (client->network.host && client->connection_subscription)
    {
        libp2p_event_unsubscribe(client->network.host, client->connection_subscription);
    }
    client->connection_subscription = NULL;

    if (client->network.host && client->ping_running && client->ping_server)
    {
        if (libp2p_ping_service_stop(client->network.host, client->ping_server) != 0)
        {
            lantern_log_warn(
                "network",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to stop libp2p ping service cleanly");
        }
        else
        {
            lantern_log_info(
                "network",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "shutdown: libp2p ping service stopped");
        }
    }
    client->ping_server = NULL;
    client->ping_running = false;

    if (client->connection_lock_initialized)
    {
        connection_counter_reset(client);
        pthread_mutex_destroy(&client->connection_lock);
        client->connection_lock_initialized = false;
    }
    else
    {
        client->connected_peers = 0;
    }
    lantern_string_list_reset(&client->connected_peer_ids);

    if (client->status_lock_initialized)
    {
        if (pthread_mutex_lock(&client->status_lock) == 0)
        {
            free(client->peer_status_entries);
            client->peer_status_entries = NULL;
            client->peer_status_count = 0;
            client->peer_status_capacity = 0;
            pthread_mutex_unlock(&client->status_lock);
        }
        else
        {
            free(client->peer_status_entries);
            client->peer_status_entries = NULL;
            client->peer_status_count = 0;
            client->peer_status_capacity = 0;
        }
        pthread_mutex_destroy(&client->status_lock);
        client->status_lock_initialized = false;
    }
    else
    {
        free(client->peer_status_entries);
        client->peer_status_entries = NULL;
        client->peer_status_count = 0;
        client->peer_status_capacity = 0;
    }

    if (client->peer_vote_lock_initialized)
    {
        if (pthread_mutex_lock(&client->peer_vote_lock) == 0)
        {
            free(client->peer_vote_stats);
            client->peer_vote_stats = NULL;
            client->peer_vote_stats_len = 0;
            client->peer_vote_stats_cap = 0;
            pthread_mutex_unlock(&client->peer_vote_lock);
        }
        else
        {
            free(client->peer_vote_stats);
            client->peer_vote_stats = NULL;
            client->peer_vote_stats_len = 0;
            client->peer_vote_stats_cap = 0;
        }
        pthread_mutex_destroy(&client->peer_vote_lock);
        client->peer_vote_lock_initialized = false;
    }
    else
    {
        free(client->peer_vote_stats);
        client->peer_vote_stats = NULL;
        client->peer_vote_stats_len = 0;
        client->peer_vote_stats_cap = 0;
    }

    if (client->validator_lock_initialized)
    {
        if (pthread_mutex_lock(&client->validator_lock) == 0)
        {
            free(client->validator_enabled);
            client->validator_enabled = NULL;
            pthread_mutex_unlock(&client->validator_lock);
        }
        else
        {
            free(client->validator_enabled);
            client->validator_enabled = NULL;
        }
        pthread_mutex_destroy(&client->validator_lock);
        client->validator_lock_initialized = false;
    }
    else
    {
        free(client->validator_enabled);
        client->validator_enabled = NULL;
    }

    if (client->pending_lock_initialized)
    {
        if (pthread_mutex_lock(&client->pending_lock) == 0)
        {
            pending_block_list_reset(&client->pending_blocks);
            pthread_mutex_unlock(&client->pending_lock);
        }
        else
        {
            pending_block_list_reset(&client->pending_blocks);
        }
        pthread_mutex_destroy(&client->pending_lock);
        client->pending_lock_initialized = false;
    }
    else
    {
        pending_block_list_reset(&client->pending_blocks);
    }
    lantern_string_list_reset(&client->dialer_peers);
    lantern_string_list_reset(&client->status_failure_peer_ids);
    lantern_string_list_reset(&client->bootnodes);
    free(client->data_dir);
    client->data_dir = NULL;
    free(client->node_id);
    client->node_id = NULL;
    free(client->listen_address);
    client->listen_address = NULL;
    free(client->devnet);
    client->devnet = NULL;

    reset_genesis_paths(&client->genesis_paths);
    lantern_genesis_artifacts_reset(&client->genesis);
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: stopping request/response service");
    lantern_reqresp_service_reset(&client->reqresp);
    lantern_reqresp_service_init(&client->reqresp);
    client->reqresp_running = false;
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: request/response service stopped");
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: stopping gossipsub");
    lantern_gossipsub_service_reset(&client->gossip);
    client->gossip_running = false;
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: gossipsub stopped");
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: resetting libp2p host");
    lantern_libp2p_host_reset(&client->network);
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: libp2p host reset");
    lantern_enr_record_reset(&client->local_enr);
    memset(client->node_private_key, 0, sizeof(client->node_private_key));
    client->has_node_private_key = false;
    if (client->has_state)
    {
        lantern_state_reset(&client->state);
        client->has_state = false;
    }
    else
    {
        lantern_state_reset(&client->state);
    }
    if (client->state_lock_initialized)
    {
        pthread_mutex_destroy(&client->state_lock);
        client->state_lock_initialized = false;
    }
    lantern_fork_choice_reset(&client->fork_choice);
    client->has_fork_choice = false;
    reset_local_validators(client);
    lantern_validator_assignment_reset(&client->validator_assignment);
    client->has_validator_assignment = false;
    lantern_consensus_runtime_reset(&client->runtime);
    client->has_runtime = false;

    client->http_port = 0;
    client->metrics_port = 0;
    client->assigned_validators = NULL;
    lantern_log_reset_node_id();
}


/**
 * @brief Get the count of local validators.
 *
 * Returns the number of validators that this client is responsible for
 * managing (proposing blocks, creating attestations).
 *
 * @param client  Client to query
 *
 * @return Number of local validators, or 0 if client is NULL
 *
 * @note Thread safety: None required - reads immutable field after init.
 */
size_t lantern_client_local_validator_count(const struct lantern_client *client)
{
    if (!client)
    {
        return 0;
    }
    return client->local_validator_count;
}


/**
 * @brief Get a local validator by index.
 *
 * Returns a pointer to the local validator at the specified index.
 * The returned pointer is valid for the lifetime of the client.
 *
 * @param client  Client to query
 * @param index   Index of the local validator (0 to count-1)
 *
 * @return Pointer to the validator, or NULL if client is NULL or index is out of range
 *
 * @note Thread safety: None required - returns pointer to immutable data.
 */
const struct lantern_local_validator *lantern_client_local_validator(
    const struct lantern_client *client,
    size_t index)
{
    if (!client || index >= client->local_validator_count)
    {
        return NULL;
    }
    return &client->local_validators[index];
}
