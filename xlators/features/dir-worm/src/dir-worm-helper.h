void dir_worm_serialize_meta (worm_meta_t *meta, char *val);

void dir_worm_deserialize_meta (char *val, worm_meta_t *meta);

void dir_worm_serialize_state (dir_worm_reten_state_t *reten_state,
                               char *val);

void dir_worm_deserialize_state (char *val,
                                 dir_worm_reten_state_t *reten_state);

int32_t dir_worm_init_state (xlator_t *this, gf_boolean_t fop_with_fd,
                             void *file_ptr, void *meta_ptr);

int32_t dir_worm_commit_state (xlator_t *this,
                               dir_worm_reten_state_t *reten_state,
                               gf_boolean_t fop_with_fd, void *file_ptr);

int32_t dir_worm_set_state (xlator_t *this, gf_boolean_t fop_with_fd,
                            void *file_ptr,
                            dir_worm_reten_state_t *retention_state,
                            struct iatt *stbuf);

int32_t dir_worm_get_state (xlator_t *this, gf_boolean_t fop_with_fd,
                            void *file_ptr,
                            dir_worm_reten_state_t *reten_state);

void dir_worm_state_finish (xlator_t *this, gf_boolean_t fop_with_fd,
                            void *file_ptr,
                            dir_worm_reten_state_t *reten_state,
                            struct iatt *stbuf);

int dir_worm_state_transition (xlator_t *this, gf_boolean_t fop_with_fd,
                               void *file_ptr, glusterfs_fop_t op);

int32_t is_wormfile (xlator_t *this, gf_boolean_t fop_with_fd, void *file_ptr);
