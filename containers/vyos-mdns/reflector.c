#include <avahi-common/error.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/strlst.h>
#include <avahi-core/core.h>
#include <avahi-core/log.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <regex.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/prctl.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static bool failed;

static void stop(int signal_number) {
    (void) signal_number;
    stopping = 1;
}

static void log_message(AvahiLogLevel level, const char *message) {
    if (level <= AVAHI_LOG_INFO)
        fprintf(stderr, "%s\n", message);
}

static bool live_multicast_ipv4(const char *name) {
    struct ifaddrs *interfaces;
    if (getifaddrs(&interfaces) != 0)
        return false;
    bool live = false;
    for (const struct ifaddrs *link = interfaces; link; link = link->ifa_next) {
        const unsigned int required = IFF_UP | IFF_RUNNING | IFF_MULTICAST;
        if (strcasecmp(link->ifa_name, name) != 0)
            continue;
        // Avahi's interface allowlist uses a case-insensitive comparison.
        if (strcmp(link->ifa_name, name) != 0) {
            live = false;
            break;
        }
        if (link->ifa_addr && link->ifa_addr->sa_family == AF_INET
                && (link->ifa_flags & required) == required)
            live = true;
    }
    freeifaddrs(interfaces);
    return live;
}

static int parse_names(const char *value, const char *expression, unsigned int limit,
                       bool verify_interface, AvahiStringList **list) {
    if (!value || strlen(value) > limit * 80)
        return -1;
    regex_t grammar;
    const int flags = REG_EXTENDED | REG_NOSUB | (verify_interface ? 0 : REG_ICASE);
    if (regcomp(&grammar, expression, flags) != 0)
        return -1;
    char *buffer = strdup(value);
    if (!buffer) {
        regfree(&grammar);
        return -1;
    }
    int count = 0;
    char *next = buffer;
    char *name;
    while ((name = strsep(&next, ",")) != NULL) {
        if ((unsigned int) count == limit || regexec(&grammar, name, 0, NULL, 0) != 0
                || (verify_interface && !live_multicast_ipv4(name))) {
            count = -1;
            break;
        }
        for (const AvahiStringList *item = *list; item; item = item->next) {
            if (strcasecmp((const char *) item->text, name) == 0) {
                count = -1;
                break;
            }
        }
        if (count < 0)
            break;
        AvahiStringList *added = avahi_string_list_add(*list, name);
        if (!added) {
            count = -1;
            break;
        }
        *list = added;
        count++;
    }
    free(buffer);
    regfree(&grammar);
    return count;
}

static void observe(AvahiServer *server, AvahiServerState state, void *userdata) {
    (void) userdata;
    if (state == AVAHI_SERVER_FAILURE || state == AVAHI_SERVER_COLLISION) {
        fprintf(stderr, "Avahi reflector failure: %s\n", avahi_strerror(avahi_server_errno(server)));
        failed = true;
    }
}

int main(void) {
    if (geteuid() == 0) {
        fprintf(stderr, "Run the reflector under its dedicated non-root account\n");
        return EXIT_FAILURE;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("Refusing to run without no-new-privileges");
        return EXIT_FAILURE;
    }
    avahi_set_log_function(log_message);
    AvahiServerConfig config;
    avahi_server_config_init(&config);
    const char *mode = getenv("UXG_MDNS_MODE");
    const char *filters = getenv("UXG_MDNS_FILTERS");
    int filter_count = -1;
    if (mode && strcmp(mode, "all") == 0 && !filters) {
        filter_count = 0;
    } else if (mode && strcmp(mode, "specific") == 0) {
        filter_count = parse_names(filters, "^_[a-zA-Z0-9]([a-zA-Z0-9_-]{0,60}[a-zA-Z0-9])?\\._(tcp|udp)\\.local$",
                                   512, false, &config.reflect_filters);
    }
    if (filter_count < 0) {
        fprintf(stderr, "Invalid reflector mode or service filter list\n");
        avahi_server_config_free(&config);
        return EXIT_FAILURE;
    }
    const char *interfaces = getenv("UXG_MDNS_INTERFACES");
    const int interface_count = parse_names(interfaces, "^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$",
                                            50, true, &config.allow_interfaces);
    if (interface_count < 2) {
        fprintf(stderr, "Select two or more distinct active multicast IPv4 interfaces\n");
        avahi_server_config_free(&config);
        return EXIT_FAILURE;
    }
    config.use_ipv4 = 1;
    config.use_ipv6 = 0;
    config.enable_reflector = 1;
    config.reflect_ipv = 0;
    config.enable_wide_area = 0;
    config.disable_publishing = 1;
    config.disallow_other_stacks = 1;
    struct sigaction action = { .sa_handler = stop };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 || sigaction(SIGTERM, &action, NULL) != 0) {
        avahi_server_config_free(&config);
        return EXIT_FAILURE;
    }
    AvahiSimplePoll *poll = avahi_simple_poll_new();
    if (!poll) {
        avahi_server_config_free(&config);
        return EXIT_FAILURE;
    }
    int error = 0;
    AvahiServer *server = avahi_server_new(avahi_simple_poll_get(poll), &config, observe, NULL, &error);
    avahi_server_config_free(&config);
    if (!server) {
        fprintf(stderr, "Could not start Avahi reflector: %s\n", avahi_strerror(error));
        avahi_simple_poll_free(poll);
        return EXIT_FAILURE;
    }
    printf("UXG_MDNS_INITIALIZED mode=%s interfaces=%s filters=%s\n",
           mode, interfaces, filters ? filters : "-");
    fflush(stdout);
    int result = 0;
    while (!stopping && !failed && result == 0)
        result = avahi_simple_poll_iterate(poll, 1000);
    avahi_server_free(server);
    avahi_simple_poll_free(poll);
    return failed || (result != 0 && !stopping) ? EXIT_FAILURE : EXIT_SUCCESS;
}
