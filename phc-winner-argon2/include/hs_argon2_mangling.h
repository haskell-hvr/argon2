#if !defined(HS_ARGON2_MANGLING_H)
#define HS_ARGON2_MANGLING_H

/* local symbol mangling */
#define blake2b              hs_argon2__blake2b
#define blake2b_final        hs_argon2__blake2b_final
#define blake2b_init         hs_argon2__blake2b_init
#define blake2b_init_key     hs_argon2__blake2b_init_key
#define blake2b_init_param   hs_argon2__blake2b_init_param
#define blake2b_long         hs_argon2__blake2b_long
#define blake2b_update       hs_argon2__blake2b_update

#define allocate_memory       hs_argon2__allocate_memory
#define argon2_ctx            hs_argon2__argon2_ctx
#define argon2_encodedlen     hs_argon2__argon2_encodedlen
#define argon2_error_message  hs_argon2__argon2_error_message
#define argon2_hash           hs_argon2__argon2_hash
#define argon2_thread_create  hs_argon2__argon2_thread_create
#define argon2_thread_exit    hs_argon2__argon2_thread_exit
#define argon2_thread_join    hs_argon2__argon2_thread_join
#define argon2_type2string    hs_argon2__argon2_type2string
#define argon2_verify         hs_argon2__argon2_verify
#define argon2_verify_ctx     hs_argon2__argon2_verify_ctx
#define argon2d_ctx           hs_argon2__argon2d_ctx
#define argon2d_hash_encoded  hs_argon2__argon2d_hash_encoded
#define argon2d_hash_raw      hs_argon2__argon2d_hash_raw
#define argon2d_verify        hs_argon2__argon2d_verify
#define argon2d_verify_ctx    hs_argon2__argon2d_verify_ctx
#define argon2i_ctx           hs_argon2__argon2i_ctx
#define argon2i_hash_encoded  hs_argon2__argon2i_hash_encoded
#define argon2i_hash_raw      hs_argon2__argon2i_hash_raw
#define argon2i_verify        hs_argon2__argon2i_verify
#define argon2i_verify_ctx    hs_argon2__argon2i_verify_ctx
#define argon2id_ctx          hs_argon2__argon2id_ctx
#define argon2id_hash_encoded hs_argon2__argon2id_hash_encoded
#define argon2id_hash_raw     hs_argon2__argon2id_hash_raw
#define argon2id_verify       hs_argon2__argon2id_verify
#define argon2id_verify_ctx   hs_argon2__argon2id_verify_ctx
#define b64len                hs_argon2__b64len
#define clear_internal_memory hs_argon2__clear_internal_memory
#define copy_block            hs_argon2__copy_block
#define decode_string         hs_argon2__decode_string
#define encode_string         hs_argon2__encode_string
#define fill_first_blocks     hs_argon2__fill_first_blocks
#define fill_memory_blocks    hs_argon2__fill_memory_blocks
#define fill_segment          hs_argon2__fill_segment
#define finalize              hs_argon2__finalize
#define free_memory           hs_argon2__free_memory
#define index_alpha           hs_argon2__index_alpha
#define init_block_value      hs_argon2__init_block_value
#define initial_hash          hs_argon2__initial_hash
#define initialize            hs_argon2__initialize
#define numlen                hs_argon2__numlen
#define secure_wipe_memory    hs_argon2__secure_wipe_memory
#define validate_inputs       hs_argon2__validate_inputs
#define xor_block             hs_argon2__xor_block
  
#endif
