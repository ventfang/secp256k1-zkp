/**********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille, Gregory Maxwell             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include "secp256k1.c"
#include "include/secp256k1.h"
#include "include/secp256k1_commitment.h"
#include "include/secp256k1_bulletproofs.h"
#include "testrand_impl.h"

static secp256k1_context *ctx = NULL;
unsigned char zero_blind[32] = {0};

static void counting_illegal_callback_fn(const char* str, void* data) {
    /* Dummy callback function that just counts. */
    int32_t *p;
    (void)str;
    p = data;
    (*p)++;
}

static void uncounting_illegal_callback_fn(const char* str, void* data) {
    /* Dummy callback function that just counts (backwards). */
    int32_t *p;
    (void)str;
    p = data;
    (*p)--;
}

void printHex(unsigned char data[]) {
    printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);
    data += 16;
    printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);
}

const secp256k1_generator* G = &secp256k1_generator_const_g;
const secp256k1_generator* H = &secp256k1_generator_const_h;

void test_blind_generator_blind_sum(){
    uint64_t val = 10;
    unsigned char vblind[32];
    unsigned char out[64];
    unsigned char ablind[32];
    unsigned char* pvblind = vblind;
    unsigned char* pablind = ablind;
    secp256k1_generator Gasset, GassetOld;
    secp256k1_pedersen_commitment Cval, CvalOld, Csum;
    secp256k1_pedersen_commitment* cpositive[1] = {&Cval};
    secp256k1_pedersen_commitment* cnegtive[1] = {&CvalOld};

    secp256k1_rand256(vblind);
    CHECK(secp256k1_pedersen_blind_sum(ctx, ablind, &pvblind, 1, 1) != 0);

    secp256k1_generator_generate(ctx, &GassetOld, ablind);
    CHECK(secp256k1_pedersen_commit(ctx, &CvalOld, vblind, val, &GassetOld, G) == 1);
    //secp256k1_pedersen_commitment_serialize(ctx, out, &CvalOld);
    printf("before secp256k1_pedersen_blind_generator_blind_sum\n");
    printf("value blind: ");printHex(vblind);printf("\n");
    printf("asset blind: ");printHex(ablind);printf("\n");
    printf("     commit: ");printHex(out);printf("\n");


    CHECK(secp256k1_pedersen_blind_generator_blind_sum(ctx, &val, &pablind, &pvblind, 1, 0) != 0);
    //secp256k1_generator_generate_blinded(ctx, &Gasset, zero_blind, ablind);
    secp256k1_generator_generate(ctx, &Gasset, ablind);
    CHECK(secp256k1_pedersen_commit(ctx, &Cval, vblind, val, &GassetOld, G) == 1);
    secp256k1_pedersen_commitment_serialize(ctx, out, &Cval);
    printf("after secp256k1_pedersen_blind_generator_blind_sum\n");
    printf("value blind: ");printHex(vblind);printf("\n");
    printf("asset blind: ");printHex(ablind);printf("\n");
    printf("     commit: ");printHex(out);printf("\n");

    secp256k1_pedersen_commit_sum(ctx, &Csum, &cpositive, 1, &cnegtive, 1);
    secp256k1_pedersen_commitment_serialize(ctx, out, &Csum);
    printf("sum commit:? ");printHex(out);printf("\n");
    printf("\n=========================\n");
}

void test_compatable_with_elements() {
    secp256k1_pedersen_commitment commit;
    unsigned char out[64];

    {
        uint64_t value = 0;
        secp256k1_pubkey pubkey;
        unsigned char blind[] = {0x16, 0xa2, 0xff, 0x4f, 0xc4, 0x43, 0xcf, 0x61, 0xf2, 0xf4, 0x60, 0x7e, 0xba, 0x06, 0x0d, 0x69, 0x46, 0x80, 0x45, 0x8b, 0xca, 0x75, 0x75, 0x91, 0xb5, 0xcf, 0xc9, 0xd4, 0xe3, 0x0d, 0xe2, 0x56};
        //unsigned char blind[32] = {0};

        secp256k1_gej rj;
        secp256k1_ge r;
        secp256k1_ge blind_genp;
        secp256k1_scalar sec;
        int overflow;

        CHECK(secp256k1_pedersen_commit(ctx, &commit, blind, value, H, G) == 1);
        secp256k1_pedersen_commitment_serialize(ctx, out, &commit);
        printf("test_compatable_with_elements: \n");
        printf("value  = %lld\n", value);
        printf("blind  = ");printHex(blind);printf("\n");
        printf("blindG = ");printHex(commit.data);printHex(commit.data+32);printf("\n");
        printf("commit = ");printHex(out);printf("\n\n");

        secp256k1_generator_load(&blind_genp, G);
        secp256k1_scalar_set_b32(&sec, blind, &overflow);
        secp256k1_ecmult_const(&rj, &blind_genp, &sec, 256);
        printf("blind  = ");printHex(blind);printf("\n");
        if (!secp256k1_gej_is_infinity(&rj)) {
            secp256k1_ge_set_gej(&r, &rj);
            secp256k1_pedersen_commitment_save(&commit, &r);
            secp256k1_pedersen_commitment_serialize(ctx, out, &commit);
            printf("blindG = ");printHex(commit.data);printHex(commit.data+32);printf("\n");
            printf("commit = ");printHex(out);printf("\n");
        }
        printf("\n");

        printf("test ec pubkey:\n");
        printf("priv key: ");printHex(blind);printf("\n");
        secp256k1_ec_pubkey_create(ctx, &pubkey, blind);
        printf("pub  key: ");printHex(pubkey.data);printHex(pubkey.data+32);printf("\n");
        secp256k1_pubkey_to_pedersen_commitment(ctx, &commit, &pubkey);
        secp256k1_pedersen_commitment_serialize(ctx, out, &commit);
        //secp256k1_ec_pubkey_serialize(ctx, out, 32, &pubkey, SECP256K1_EC_COMPRESSED);
        printf("commit:   ");printHex(out);printf("\n");

        {
            secp256k1_ecdsa_signature sign;
            secp256k1_ecdsa_sign(ctx, &sign, blind, blind, nonce_function_rfc6979, NULL);
            CHECK(secp256k1_ecdsa_verify(ctx, &sign, blind, &pubkey) == 1);
        }
    }
    printf("\n=========================\n");

    /*output:
    test_compatable_with_elements:
    0
    f5ecde92b24c662a0843e40fa8517236
    09a0a594531a2a20e7b9dd72f4953f2e
    test ec pubkey:
    priv key: f5ecde92b24c662a0843e40fa8517236
    pub  key: 1fbb7e35aed6c02a57438697289312c6eefca7f2a8f88481cbe6bb462e8029f8
    commit: 09bb7e35aed6c02a57438697289312c6
    */
}

const int MAX_WIDTH = 1 << 20;
const int SCRATCH_SPACE_SIZE = 268435456;//256 * MAX_WIDTH;
const int MAX_GENERATORS = 256;
const int SINGLE_BULLET_PROOF_SIZE = 675;
void test_bulletproofs() {
    printf("bulletproofs\n");
    unsigned char proof[SINGLE_BULLET_PROOF_SIZE];
    size_t plen = SINGLE_BULLET_PROOF_SIZE;
    unsigned char blinding[32];
    unsigned char* pblinding[32] = {blinding};
    unsigned char blind_out[64];
    unsigned char rewind_nonce[32];
    unsigned char private_nonce[32];
    uint64_t value = 12345678;
    uint64_t rewind_value;
    secp256k1_pedersen_commitment commit;
    secp256k1_scratch_space* scratch;
    secp256k1_bulletproof_generators* gens;

    secp256k1_rand256(blinding);
    secp256k1_rand256(rewind_nonce);
    secp256k1_rand256(private_nonce);
    secp256k1_pedersen_commit(ctx, &commit, blinding, value, H, G);
    scratch = secp256k1_scratch_space_create(ctx, SCRATCH_SPACE_SIZE);
    gens = secp256k1_bulletproof_generators_create(ctx, G, MAX_GENERATORS);

    printf("value: %llu\n", value);
    printf("blind: ");printHex(blinding);printf("\n");

    CHECK(1 == secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, proof, &plen,
        NULL, NULL, NULL, &value, NULL, pblinding, NULL, 1, H, 64,
        blinding, blinding, NULL, 0, NULL));
    CHECK(1 == secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof, plen, NULL, &commit, 1, 64, H, NULL, 0));


    value = -1;
    secp256k1_pedersen_commit(ctx, &commit, blinding, value, H, G);
    CHECK(1 == secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, proof, &plen,
        NULL, NULL, NULL, &value, NULL, pblinding, NULL, 1, H, 64,
        private_nonce, private_nonce, NULL, 0, NULL));
    CHECK(1 == secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof, plen, NULL, &commit, 1, 63, H, NULL, 0));
    CHECK(1 == secp256k1_bulletproof_rangeproof_rewind(ctx, &rewind_value, blind_out, proof, plen, 0, &commit,
        H, private_nonce, NULL, 0, NULL));
    CHECK(value == rewind_value);
    CHECK(memcmp(blind_out, blinding, 32) == 0);
    printf("value: %llu\n", value);
    printf("rewind_value: %llu, %llx\n", rewind_value, rewind_value);
    printf("rewind_blind: ");printHex(blind_out);printf("\n");


    secp256k1_scratch_space_destroy(scratch);
}

int main() {
    unsigned char out[64];
    unsigned char txin_blind[32] = {0};
    unsigned char txout1_blind[32] = {0};
    unsigned char txout2_blind[32] = {0};
    uint64_t txin_val = 500000 * 1e8;
    uint64_t txout1_val = 200000 * 1e8;
    uint64_t txout2_val = 300000 * 1e8;
    secp256k1_pedersen_commitment Ctxin;
    secp256k1_pedersen_commitment Ctxout1;
    secp256k1_pedersen_commitment Ctxout2;
    unsigned char* blind[3] = {txout2_blind, txout1_blind, txin_blind};
    unsigned char blindsum[32];
    secp256k1_pedersen_commitment Cblind;

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    test_compatable_with_elements();

    secp256k1_rand256(txin_blind);
    secp256k1_rand256(txout1_blind);
    secp256k1_rand256(txout2_blind);

    CHECK(secp256k1_pedersen_commit(ctx, &Ctxin, txin_blind, txin_val, H, G) == 1);
    CHECK(secp256k1_pedersen_commit(ctx, &Ctxout1, txout1_blind, txout1_val, H, G) == 1);
    CHECK(secp256k1_pedersen_commit(ctx, &Ctxout2, txout2_blind, txout2_val, H, G) == 1);

    CHECK(secp256k1_pedersen_commitment_serialize(ctx, out, &Ctxin) == 1);
    printf("txin:   blind = ");printHex(txin_blind);printf(" value = %llu ", txin_val);printf("commit = ");printHex(out);printf("\n");
    CHECK(secp256k1_pedersen_commitment_serialize(ctx, out, &Ctxout1) == 1);
    printf("txout1: blind = ");printHex(txout1_blind);printf(" value = %llu ", txout1_val);printf("commit = ");printHex(out);printf("\n");
    CHECK(secp256k1_pedersen_commitment_serialize(ctx, out, &Ctxout2) == 1);
    printf("txout2: blind = ");printHex(txout2_blind);printf(" value = %llu ", txout2_val);printf("commit = ");printHex(out);printf("\n");

    secp256k1_pedersen_commitment* Cout[2];
    secp256k1_pedersen_commitment* Cin[1];
    secp256k1_pedersen_commitment Csum;
    Cin[0] = &Ctxin;
    Cout[0] = &Ctxout1;
    Cout[1] = &Ctxout2;

    secp256k1_pedersen_commit_sum(ctx, &Csum, &Cout, 2, &Cin, 1);
    CHECK(secp256k1_pedersen_commitment_serialize(ctx, out, &Csum) == 1);
    printf("   sum commit = ");printHex(out);printf("\n");
    printf("\n=========================\n");

    txin_val = 10 * 1e8;
    txout1_val = 7 * 1e8;
    txout2_val = 3 * 1e8;

    CHECK(secp256k1_pedersen_commit(ctx, &Ctxin, txin_blind, txin_val, H, G) == 1);
    CHECK(secp256k1_pedersen_commit(ctx, &Ctxout1, txout1_blind, txout1_val, H, G) == 1);
    CHECK(secp256k1_pedersen_commit(ctx, &Ctxout2, txout2_blind, txout2_val, H, G) == 1);

    CHECK(secp256k1_pedersen_commitment_serialize(ctx, out, &Ctxin) == 1);
    printf("txin:   blind = ");printHex(txin_blind);printf(" value = %llu ", txin_val);printf("commit = ");printHex(out);printf("\n");
    CHECK(secp256k1_pedersen_commitment_serialize(ctx, out, &Ctxout1) == 1);
    printf("txout1: blind = ");printHex(txout1_blind);printf(" value = %llu ", txout1_val);printf("commit = ");printHex(out);printf("\n");
    CHECK(secp256k1_pedersen_commitment_serialize(ctx, out, &Ctxout2) == 1);
    printf("txout2: blind = ");printHex(txout2_blind);printf(" value = %llu ", txout2_val);printf("commit = ");printHex(out);printf("\n");

    secp256k1_pedersen_commit_sum(ctx, &Csum, &Cout, 2, &Cin, 1);
    CHECK(secp256k1_pedersen_commitment_serialize(ctx, out, &Csum) == 1);
    printf("   sum commit = ");printHex(out);printf("\n");
    printf("\n=========================\n");

    secp256k1_pedersen_blind_sum(ctx, &blindsum, &blind, 3, 2);
    CHECK(secp256k1_pedersen_commitment_serialize(ctx, out, &blindsum) == 1);
    printf("sum blind        = ");printHex(out);printf("\n");
    CHECK(secp256k1_pedersen_commit(ctx, &Cblind, blindsum, 0, H, G) == 1);
    CHECK(secp256k1_pedersen_commitment_serialize(ctx, out, &Cblind) == 1);
    printf("sum blind commit = ");printHex(out);printf("\n");
    printf("\n=========================\n");

    {
        //aG + 1H + bG + 2H - cG + 3H = (a+b-c)G + (1+2-3)H = (a+b+c)G
        secp256k1_pedersen_commitment* C1[1] = {&Csum};
        secp256k1_pedersen_commitment* C2[1] = {&Cblind};
        secp256k1_pedersen_commitment Cres;
        secp256k1_pedersen_commit_sum(ctx, &Cres, &C2, 1, &C1, 1);
        CHECK(secp256k1_pedersen_commitment_serialize(ctx, out, &Cres) == 1);
        printf("sum commit - sum blind commit = ");printHex(out);printf("\n");
        printHex(Cres.data);printHex(Cres.data+32);printf("\n");
        printf("\n=========================\n");
    }

    test_blind_generator_blind_sum();

    test_bulletproofs();

    /* shutdown */
    secp256k1_context_destroy(ctx);

    printf("no problems found\n");
    return 0;
}