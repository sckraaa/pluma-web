# The site as a server serves it: Caddy with the files of one build in /srv.
# The server repository brings the Caddyfile (TLS, /apiws to the gateway);
# this image carries only the site (README, The site). Built by the image job
# of the web workflow for builds for the server.
FROM caddy:2.11.6-alpine@sha256:d44355d3c2149dc580ce2cac735955d1c08d3d00882c30489c241aa51a5c10d9
# The build context is the extracted site.
COPY . /srv/
