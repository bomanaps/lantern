#include "tests/support/fixture_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            fprintf(stderr, "check failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
            abort();                                                                 \
        }                                                                            \
    } while (0)

static char *copy_text(const char *text) {
    size_t len = strlen(text);
    char *copy = (char *)malloc(len + 1u);
    CHECK(copy != NULL);
    memcpy(copy, text, len + 1u);
    return copy;
}

static void expect_lstar_signature_proof_alias(void) {
    static const char json[] =
        "{"
        "\"participants\":{\"data\":[false,true,true]},"
        "\"proof\":{\"data\":\"0x01020304\"}"
        "}";

    struct lantern_fixture_document doc;
    LanternAggregatedSignatureProof proof;

    memset(&doc, 0, sizeof(doc));
    lantern_aggregated_signature_proof_init(&proof);

    CHECK(lantern_fixture_document_init(&doc, copy_text(json)) == 0);
    CHECK(lantern_fixture_parse_signature_proof(&doc, 0, &proof) == 0);

    CHECK(proof.participants.bit_length == 3u);
    CHECK(!lantern_bitlist_get(&proof.participants, 0u));
    CHECK(lantern_bitlist_get(&proof.participants, 1u));
    CHECK(lantern_bitlist_get(&proof.participants, 2u));

    CHECK(proof.proof_data.length == 4u);
    CHECK(proof.proof_data.data != NULL);
    CHECK(proof.proof_data.data[0] == 0x01u);
    CHECK(proof.proof_data.data[1] == 0x02u);
    CHECK(proof.proof_data.data[2] == 0x03u);
    CHECK(proof.proof_data.data[3] == 0x04u);

    lantern_aggregated_signature_proof_reset(&proof);
    lantern_fixture_document_reset(&doc);
}

int main(void) {
    expect_lstar_signature_proof_alias();
    return 0;
}
