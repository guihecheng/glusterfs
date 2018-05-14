#ifndef __DIR_WORM_H__
#define __DIR_WORM_H__

typedef struct {
	gf_boolean_t dir_worm_on;
	gf_boolean_t dir_worm_files_deletable;
	gf_boolean_t dir_worm_files_editable;
} dir_worm_priv_t;

typedef struct {
        uint8_t worm : 1;
        uint8_t retain : 1;
        uint64_t start_period;
        uint64_t dura_period;
} dir_worm_reten_state_t;

#endif /* __DIR_WORM_H__ */
