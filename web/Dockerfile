# syntax=docker/dockerfile:1

# The web app as the local stack serves it (#195): the production bundle, built once, behind a static server with
# the response headers of the CloudFront policy (ADR-0008), on its own origin, http://localhost:3000. In AWS the same
# bundle goes to S3 and CloudFront instead; this image is local only.

# ---- build: the bundle, with the Node version in .nvmrc (keep the two in step) ----
FROM node:26.13.0-bookworm-slim@sha256:bc0a2afd3b74ce12222fc8bab99271e66257f021078f5f4a5d687a77d280c1d9 AS build
WORKDIR /web
# Dependencies first: this layer stays cached until the lock file changes. No install scripts run (T-68).
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts --no-audit --no-fund
COPY . .
RUN npm run build

# ---- runtime: nginx, unprivileged (uid 101), read-only; config.json is mounted by compose ----
FROM nginxinc/nginx-unprivileged:1.30.6-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03
ENV NGINX_ENTRYPOINT_QUIET_LOGS=1
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /web/dist /usr/share/nginx/html
# The development config (public/config.json, for the dev server's proxy) is replaced by the mounted one.
USER 101:101
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/index.html"]
