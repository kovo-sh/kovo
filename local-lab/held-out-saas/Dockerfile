FROM node:24-bookworm-slim
WORKDIR /app
COPY . /app
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000 KOVO_LAB=1
EXPOSE 3000
USER node
CMD ["node", "server.mjs"]
