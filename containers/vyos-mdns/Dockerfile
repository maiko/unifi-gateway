FROM docker.io/library/debian@sha256:311f7a192fd9a92b165a86b32fa3aae9005b11849bfb1db2d4fd784559ee464f AS build
RUN apt-get update && apt-get install --yes --no-install-recommends gcc libc6-dev pkg-config libavahi-core-dev=0.8-10+deb12u1 && rm -rf /var/lib/apt/lists/*
COPY reflector.c /src/reflector.c
RUN cc -std=gnu11 -Wall -Wextra -Werror -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now -o /uxg-mdns /src/reflector.c $(pkg-config --cflags --libs avahi-core)

FROM docker.io/library/debian@sha256:311f7a192fd9a92b165a86b32fa3aae9005b11849bfb1db2d4fd784559ee464f
RUN apt-get update && apt-get install --yes --no-install-recommends libavahi-core7=0.8-10+deb12u1 && rm -rf /var/lib/apt/lists/*
COPY --from=build /uxg-mdns /usr/local/bin/uxg-mdns
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/uxg-mdns"]
